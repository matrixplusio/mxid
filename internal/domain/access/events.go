package access

// Domain event types emitted for the audit subsystem.
const (
	EventRequestCreated   = "access.request.created"
	EventRequestApproved  = "access.request.approved"
	EventRequestRejected  = "access.request.rejected"
	EventRequestCancelled = "access.request.cancelled"
	EventGrantActivated   = "access.grant.activated"
	EventGrantExpired     = "access.grant.expired"
	EventGrantRevoked     = "access.grant.revoked"
)
