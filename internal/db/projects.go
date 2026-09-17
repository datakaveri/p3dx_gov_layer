package db

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
)

// UpsertProject records the project_id assigned to a contract (see
// BuildContract, which mints a fresh project_id on every call) alongside who
// is participating: the output owner and the data-provider parties on that
// specific contract. Called for every contract build (draft and final,
// including "Start Again" restarts), so each contract shows up as its own
// project row linked to the providers on it. Keyed on project_id (the
// table's primary key), which is always new, so this always inserts rather
// than updating a previous project.
func (d *DB) UpsertProject(ctx context.Context, projectID, sessionID, ownerUsername string, providerUsernames []string) error {
	if providerUsernames == nil {
		providerUsernames = []string{}
	}
	raw, err := json.Marshal(providerUsernames)
	if err != nil {
		return err
	}
	_, err = d.Pool.Exec(ctx, `INSERT INTO projects
			(project_id, session_id, output_owner_username, data_provider_usernames)
			VALUES ($1, $2, $3, $4)
		ON CONFLICT (project_id) DO UPDATE SET
			output_owner_username = EXCLUDED.output_owner_username,
			data_provider_usernames = EXCLUDED.data_provider_usernames,
			updated_at = CURRENT_TIMESTAMP`,
		projectID, sessionID, ownerUsername, raw,
	)
	return err
}

// GetProjectIDBySession returns the project_id of the most recently created
// project for a session, or "" if none exists yet. A session can have several
// projects across "Start Again" restarts; this always returns the current one.
func (d *DB) GetProjectIDBySession(ctx context.Context, sessionID string) (string, error) {
	var pid string
	err := d.Pool.QueryRow(ctx, `SELECT project_id FROM projects WHERE session_id = $1 ORDER BY created_at DESC LIMIT 1`, sessionID).Scan(&pid)
	if err == pgx.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return pid, nil
}

// ProjectRow is one row of the project list: the project number, its session,
// and the data providers participating in it. Deliberately omits the output
// owner - the list is shown to the owner themselves, so it'd be redundant.
type ProjectRow struct {
	ProjectID             string   `json:"project_id"`
	SessionID             string   `json:"session_id"`
	DataProviderUsernames []string `json:"data_provider_usernames"`
}

// ListProjects returns projects newest-first. When ownerUsername is non-empty,
// only that owner's projects are returned; otherwise (the orchestrator's view)
// every project is returned.
func (d *DB) ListProjects(ctx context.Context, ownerUsername string) ([]ProjectRow, error) {
	var rows pgx.Rows
	var err error
	if ownerUsername == "" {
		rows, err = d.Pool.Query(ctx, `SELECT project_id, session_id, data_provider_usernames FROM projects ORDER BY created_at DESC`)
	} else {
		rows, err = d.Pool.Query(ctx, `SELECT project_id, session_id, data_provider_usernames FROM projects WHERE output_owner_username = $1 ORDER BY created_at DESC`, ownerUsername)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]ProjectRow, 0)
	for rows.Next() {
		var p ProjectRow
		var raw []byte
		if err := rows.Scan(&p.ProjectID, &p.SessionID, &raw); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(raw, &p.DataProviderUsernames)
		out = append(out, p)
	}
	return out, rows.Err()
}
