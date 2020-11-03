package images

import (
	"context"
	"fmt"
	"github.com/adrg/xdg"
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/grypeerr"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/presenter"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
	"github.com/containers/podman/v2/cmd/podman/registry"
	"github.com/containers/podman/v2/cmd/podman/utils"
	"github.com/containers/podman/v2/pkg/domain/entities"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"io/ioutil"
	"os"
	"path"
	"sync"
)

var (
	scanDescription = `Scan a container image for known vulnerabilities.  The image name or digest can be used.`
	scanCommand     = &cobra.Command{
		Use:   "scan [options] IMAGE",
		Short: "Scan a container image for known vulnerabilities",
		Long:  scanDescription,
		RunE:  scan,
		Example: `podman scan centos:latest
  podman scan --fail-on critical`,
	}

	imageScanCommand = &cobra.Command{
		Use:   scanCommand.Use,
		Short: scanCommand.Short,
		Long:  scanCommand.Long,
		RunE:  scanCommand.RunE,
		Example: `podman container scan --latest
  podman container start 860a4b231279 5421ab43b45
  podman container start --interactive --attach imageID`,
	}
)

var (
	scanOptions entities.ImageScanOptions
)

func scanFlags(flags *pflag.FlagSet) {
	// TODO: update default values
	flags.StringVarP(&scanOptions.Scope, "scope", "s", "squashed", fmt.Sprintf("selection of layers to analyze, options=%v", "TODO: scope.Options") )
	flags.StringVarP(&scanOptions.Output, "output", "o", "table", fmt.Sprintf("report output formatter, options=%v", "TODO: presenter.Options") )
	flags.StringVarP(&scanOptions.FailOn, "fail-on", "f", "", fmt.Sprintf("set the return code to 1 if a vulnerability is found with a severity >= the given severity, options=%v", "TODO: vulnerability.AllSeverities"))
}
func init() {
	registry.Commands = append(registry.Commands, registry.CliCommand{
		Mode:    []entities.EngineMode{entities.ABIMode, entities.TunnelMode},
		Command: scanCommand,
	})
	scanFlags(scanCommand.Flags())

	registry.Commands = append(registry.Commands, registry.CliCommand{
		Mode:    []entities.EngineMode{entities.ABIMode, entities.TunnelMode},
		Command: imageScanCommand,
		Parent:  imageCmd,
	})
	scanFlags(imageScanCommand.Flags())

}

func scan(cmd *cobra.Command, args []string) error {
	var (
		image      string
		errs utils.OutputErrors
	)

	if len(args) != 2 {
		// TODO: find right error type
		return fmt.Errorf("requires exactly one image")
	}

	presenterOption := presenter.ParseOption(scanOptions.Output)
	if presenterOption == presenter.UnknownPresenter {
		return fmt.Errorf("bad --output value '%s'", scanOptions.Output)
	}
	presenterOpt := presenterOption

	scopeOption := scope.ParseOption(scanOptions.Scope)
	if scopeOption == scope.UnknownScope {
		return fmt.Errorf("bad --scope value '%s'", scanOptions.Scope)
	}
	scopeOpt := scopeOption

	var failOnSeverity *vulnerability.Severity
	if scanOptions.FailOn != "" {
		sev := vulnerability.ParseSeverity(scanOptions.FailOn)
		if sev == vulnerability.UnknownSeverity {
			return fmt.Errorf("bad --fail-on severity value '%s'", scanOptions.FailOn)
		}
		failOnSeverity = &sev
	}

	file, err := ioutil.TempFile("dir", "prefix")
	if err != nil {
		// TODO: find the right error type for this
		return err
	}
	defer os.Remove(file.Name())

	ephemeralSaveOpts := entities.ImageSaveOptions{
		Output:            file.Name(),
	}

	err = registry.ImageEngine().Save(context.Background(), args[0], []string{image}, ephemeralSaveOpts)
	if err != nil {
		errs = append(errs, err)
	}

	var provider vulnerability.Provider
	var metadataProvider vulnerability.MetadataProvider
	var catalog *pkg.Catalog
	var theScope *scope.Scope
	var theDistro *distro.Distro
	var wg = &sync.WaitGroup{}

	wg.Add(2)

	go func() {
		defer wg.Done()

		dbCuratorCfg := db.Config{
			// TODO: make this configurable from podman
			DbDir:      path.Join(xdg.CacheHome, "grype", "db"),
			// TODO: don't hardcode this
			ListingURL: "https://toolbox-data.anchore.io/grype/databases/listing.json",
		}

		// TODO: make auto update configurable
		provider, metadataProvider, err = grype.LoadVulnerabilityDb(dbCuratorCfg, true)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to load vulnerability db: %w", err))
		}
	}()

	go func() {
		defer wg.Done()
		catalog, theScope, theDistro, err = syft.Catalog(image, scopeOpt)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to catalog: %w", err))
		}
	}()

	wg.Wait()
	if len(errs) > 0 {
		errs.PrintErrors()
	}

	matches := grype.FindVulnerabilitiesForCatalog(provider, *theDistro, catalog)

	// determine if there are any severities >= to the max allowable severity (which is optional).
	// note: until the shared file lock in sqlittle is fixed the sqlite DB cannot be access concurrently,
	// implying that the fail-on-severity check must be done before sending the presenter object.
	if hitSeverityThreshold(failOnSeverity, matches, metadataProvider) {
		errs = append(errs, grypeerr.ErrAboveSeverityThreshold)
	}

	pres := presenter.GetPresenter(presenterOpt, matches, catalog, *theScope, metadataProvider)
	err = pres.Present(os.Stdout)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed present vulnerabilities: %w", err))
	}

	return errs.PrintErrors()
}

// hitSeverityThreshold indicates if there are any severities >= to the max allowable severity (which is optional)
func hitSeverityThreshold(thresholdSeverity *vulnerability.Severity, matches match.Matches, metadataProvider vulnerability.MetadataProvider) bool {
	if thresholdSeverity != nil {
		var maxDiscoveredSeverity vulnerability.Severity
		for m := range matches.Enumerate() {
			metadata, err := metadataProvider.GetMetadata(m.Vulnerability.ID, m.Vulnerability.RecordSource)
			if err != nil {
				continue
			}
			severity := vulnerability.ParseSeverity(metadata.Severity)
			if severity > maxDiscoveredSeverity {
				maxDiscoveredSeverity = severity
			}
		}

		if maxDiscoveredSeverity >= *thresholdSeverity {
			return true
		}
	}
	return false
}
