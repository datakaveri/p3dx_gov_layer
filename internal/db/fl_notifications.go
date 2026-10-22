package db

// This file is FL-only: general-purpose notifications, used today for the
// participation-consent loop (an output owner asks a selected provider "still
// willing to join?" and the provider accepts/declines).

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

const notificationColumns = `id, recipient_id, recipient_username, sender_username,
	message, payload, read, read_at, created_at, response, response_message, responded_at`

// This Postgres server's session timezone is Asia/Kolkata (see `SHOW
// timezone`), so a "timestamp without time zone" column like created_at
// stores raw IST wall-clock digits with no zone attached. pgx always decodes
// that column type with a UTC Location regardless of the server's actual
// timezone, so without correction the JSON response tags an IST reading as
// "...Z" (UTC) and the browser then applies the IST offset a second time on
// display. asIST re-tags the same wall-clock digits with the correct zone so
// marshaling emits the right offset instead.
var istLocation = func() *time.Location {
	loc, err := time.LoadLocation("Asia/Kolkata")
	if err != nil {
		return time.FixedZone("IST", 5*3600+1800)
	}
	return loc
}()

func asIST(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	fixed := time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), istLocation)
	return &fixed
}

// fixTimezones re-tags every timestamp field scanned off this row - see asIST.
func (n *Notification) fixTimezones() {
	n.ReadAt = asIST(n.ReadAt)
	n.CreatedAt = asIST(n.CreatedAt)
	n.RespondedAt = asIST(n.RespondedAt)
}

// Notification is one row of notifications (used by get/markRead, which return
// the full row to clients).
type Notification struct {
	ID                string          `db:"id" json:"id"`
	RecipientID       string          `db:"recipient_id" json:"recipient_id"`
	RecipientUsername string          `db:"recipient_username" json:"recipient_username"`
	SenderUsername    string          `db:"sender_username" json:"sender_username"`
	Message           string          `db:"message" json:"message"`
	Payload           json.RawMessage `db:"payload" json:"payload"`
	Read              bool            `db:"read" json:"read"`
	ReadAt            *time.Time      `db:"read_at" json:"read_at"`
	CreatedAt         *time.Time      `db:"created_at" json:"created_at"`
	// Participation-consent fields: Response is null (pending) until the provider
	// answers "accepted" or "declined"; ResponseMessage is their optional reason.
	Response        *string    `db:"response" json:"response"`
	ResponseMessage *string    `db:"response_message" json:"response_message"`
	RespondedAt     *time.Time `db:"responded_at" json:"responded_at"`
}

// CreatedNotification is the camelCase object returned by createNotification (the
// shape the Node code returned for each created notification).
type CreatedNotification struct {
	ID                string          `json:"id"`
	RecipientID       string          `json:"recipientId"`
	RecipientUsername string          `json:"recipientUsername"`
	SenderUsername    string          `json:"senderUsername"`
	Message           string          `json:"message"`
	Payload           json.RawMessage `json:"payload"`
	Read              bool            `json:"read"`
	CreatedAt         string          `json:"created_at"`
}

// CreateNotification inserts one notification and returns the created object.
// Mirrors createNotification().
func (d *DB) CreateNotification(ctx context.Context, recipientID, recipientUsername, senderUsername, message string, payload json.RawMessage) (*CreatedNotification, error) {
	id := newID("notif", 6)
	pl := jsonbOr(payload, "{}")
	_, err := d.Pool.Exec(ctx, `INSERT INTO notifications
		(id, recipient_id, recipient_username, sender_username, message, payload)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		id, recipientID, recipientUsername, senderUsername, message, pl)
	if err != nil {
		return nil, err
	}
	return &CreatedNotification{
		ID:                id,
		RecipientID:       recipientID,
		RecipientUsername: recipientUsername,
		SenderUsername:    senderUsername,
		Message:           message,
		Payload:           json.RawMessage(pl),
		Read:              false,
		CreatedAt:         time.Now().UTC().Format(time.RFC3339Nano),
	}, nil
}

// GetNotificationsForUser returns up to 50 notifications for a recipient,
// newest-first. Mirrors getNotificationsForUser().
func (d *DB) GetNotificationsForUser(ctx context.Context, username string) ([]Notification, error) {
	rows, err := d.Pool.Query(ctx, `SELECT `+notificationColumns+`
		FROM notifications WHERE recipient_username = $1 ORDER BY created_at DESC LIMIT 50`, username)
	if err != nil {
		return nil, err
	}
	notifications, err := pgx.CollectRows(rows, pgx.RowToStructByName[Notification])
	if err != nil {
		return nil, err
	}
	for i := range notifications {
		notifications[i].fixTimezones()
	}
	return notifications, nil
}

// MarkNotificationAsRead flags a notification read for its owner, returning the
// updated row or (nil, nil) when not found. Mirrors markNotificationAsRead().
func (d *DB) MarkNotificationAsRead(ctx context.Context, notificationID, username string) (*Notification, error) {
	rows, err := d.Pool.Query(ctx, `UPDATE notifications SET read = true, read_at = NOW()
		WHERE id = $1 AND recipient_username = $2
		RETURNING `+notificationColumns, notificationID, username)
	if err != nil {
		return nil, err
	}
	n, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[Notification])
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	n.fixTimezones()
	return &n, nil
}

// RespondToNotification records a provider's participation answer ("accepted" or
// "declined") plus an optional free-text reason for the owner, and marks the
// notification read. Scoped to the recipient so a user can only answer their own.
// Returns the updated row, or (nil, nil) when no such notification exists.
func (d *DB) RespondToNotification(ctx context.Context, notificationID, username, response, message string) (*Notification, error) {
	rows, err := d.Pool.Query(ctx, `UPDATE notifications
		SET response = $1, response_message = $2, responded_at = NOW(),
		    read = true, read_at = COALESCE(read_at, NOW())
		WHERE id = $3 AND recipient_username = $4
		RETURNING `+notificationColumns, response, message, notificationID, username)
	if err != nil {
		return nil, err
	}
	n, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[Notification])
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	n.fixTimezones()
	return &n, nil
}

// GetNotificationsBySender returns up to 200 notifications a user has sent,
// newest-first — used by the output owner to see each selected provider's
// participation response (status + reason).
func (d *DB) GetNotificationsBySender(ctx context.Context, senderUsername string) ([]Notification, error) {
	rows, err := d.Pool.Query(ctx, `SELECT `+notificationColumns+`
		FROM notifications WHERE sender_username = $1 ORDER BY created_at DESC LIMIT 200`, senderUsername)
	if err != nil {
		return nil, err
	}
	notifications, err := pgx.CollectRows(rows, pgx.RowToStructByName[Notification])
	if err != nil {
		return nil, err
	}
	for i := range notifications {
		notifications[i].fixTimezones()
	}
	return notifications, nil
}

// SupersedeContractSignRequests marks every CONTRACT_SIGN notification for
// contractID answered "superseded" — after the contract is re-hashed, those
// requests carry a stale hash and new ones replace them. Returns how many.
func (d *DB) SupersedeContractSignRequests(ctx context.Context, contractID string) (int64, error) {
	tag, err := d.Pool.Exec(ctx, `UPDATE notifications
		SET response = 'superseded', response_message = 'contract changed; a new sign request replaces this one',
		    responded_at = NOW(), read = true, read_at = COALESCE(read_at, NOW())
		WHERE payload->>'type' = 'CONTRACT_SIGN' AND payload->>'contract_id' = $1
		  AND response IS DISTINCT FROM 'superseded'`, contractID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ---------------------------------------------------------------------------
// Participation negotiation. A provider gets one free decline per FL
// session: declining a second time removes them from the session — they're
// never invited to it again. A provider who's only ever said willing is
// never warned or removed.

// CountParticipationRequests returns how many participation_request
// notifications username has already received for submissionID.
func (d *DB) CountParticipationRequests(ctx context.Context, username, submissionID string) (int, error) {
	var n int
	err := d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM notifications
		WHERE recipient_username = $1
		  AND payload->>'kind' = 'participation_request'
		  AND payload->>'submission_id' = $2`, username, submissionID).Scan(&n)
	return n, err
}

// CountParticipationDeclines returns how many participation asks (requests
// or updated lists) username has declined for submissionID.
func (d *DB) CountParticipationDeclines(ctx context.Context, username, submissionID string) (int, error) {
	var n int
	err := d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM notifications
		WHERE recipient_username = $1
		  AND payload->>'kind' IN ('participation_request', 'participation_update')
		  AND payload->>'submission_id' = $2
		  AND response = 'declined'`, username, submissionID).Scan(&n)
	return n, err
}

// RemovedProvider is one row of fl_session_removed_providers.
type RemovedProvider struct {
	SubmissionID string     `db:"submission_id" json:"submission_id"`
	Username     string     `db:"username" json:"username"`
	Reason       *string    `db:"reason" json:"reason"`
	RemovedAt    *time.Time `db:"removed_at" json:"removed_at"`
}

// RemoveProviderFromSession records username as removed from submissionID.
// Returns false if they were already removed.
func (d *DB) RemoveProviderFromSession(ctx context.Context, submissionID, username, reason string) (bool, error) {
	tag, err := d.Pool.Exec(ctx, `INSERT INTO fl_session_removed_providers
		(submission_id, username, reason) VALUES ($1, $2, $3)
		ON CONFLICT (submission_id, username) DO NOTHING`, submissionID, username, reason)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// GetRemovedProviders lists the providers removed from submissionID.
func (d *DB) GetRemovedProviders(ctx context.Context, submissionID string) ([]RemovedProvider, error) {
	rows, err := d.Pool.Query(ctx, `SELECT submission_id, username, reason, removed_at
		FROM fl_session_removed_providers WHERE submission_id = $1 ORDER BY removed_at`, submissionID)
	if err != nil {
		return nil, err
	}
	removed, err := pgx.CollectRows(rows, pgx.RowToStructByName[RemovedProvider])
	if err != nil {
		return nil, err
	}
	for i := range removed {
		removed[i].RemovedAt = asIST(removed[i].RemovedAt)
	}
	return removed, nil
}

// GetLatestParticipationRequests returns, for submissionID, each recipient's
// most recent participation_request (one row per recipient).
func (d *DB) GetLatestParticipationRequests(ctx context.Context, submissionID string) ([]Notification, error) {
	rows, err := d.Pool.Query(ctx, `SELECT DISTINCT ON (recipient_username) `+notificationColumns+`
		FROM notifications
		WHERE payload->>'kind' = 'participation_request' AND payload->>'submission_id' = $1
		ORDER BY recipient_username, created_at DESC`, submissionID)
	if err != nil {
		return nil, err
	}
	notifications, err := pgx.CollectRows(rows, pgx.RowToStructByName[Notification])
	if err != nil {
		return nil, err
	}
	for i := range notifications {
		notifications[i].fixTimezones()
	}
	return notifications, nil
}

// GetNotificationForRecipient returns one notification addressed to username,
// or (nil, nil) when not found.
func (d *DB) GetNotificationForRecipient(ctx context.Context, notificationID, username string) (*Notification, error) {
	rows, err := d.Pool.Query(ctx, `SELECT `+notificationColumns+`
		FROM notifications WHERE id = $1 AND recipient_username = $2`, notificationID, username)
	if err != nil {
		return nil, err
	}
	n, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[Notification])
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	n.fixTimezones()
	return &n, nil
}

// HasNewerParticipationAsk reports whether n's recipient has a
// participation_request or participation_update for submissionID created
// after n — i.e. n has been replaced and should no longer be answered.
func (d *DB) HasNewerParticipationAsk(ctx context.Context, n *Notification, submissionID string) (bool, error) {
	var newer bool
	err := d.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM notifications
		WHERE recipient_username = $1
		  AND payload->>'kind' IN ('participation_request', 'participation_update')
		  AND payload->>'submission_id' = $2
		  AND id <> $3
		  AND created_at > (SELECT created_at FROM notifications WHERE id = $3))`,
		n.RecipientUsername, submissionID, n.ID).Scan(&newer)
	return newer, err
}
