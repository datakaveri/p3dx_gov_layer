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
