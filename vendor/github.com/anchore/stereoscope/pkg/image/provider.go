package image

// Provider is an abstraction for any object that provides image objects (e.g. the docker daemon API, a tar file of
// an OCI image, podman varlink API, etc.).
type Provider interface {
	Provide() (*Image, error)
}
