package db

import (
	"sort"
	"sync"
	"time"
)

// formsCache holds form data pushed here by aaa (the store of record). It
// replaces the old pull-based HTTP client: instead of the gov layer calling
// out to aaa on every read, aaa POSTs each submission/provider form here as
// soon as it's created (see httpapi/forms_ingest.go), and FL orchestration
// reads from this local, in-memory copy. It is not a form store in its own
// right — it holds no data aaa didn't already persist, and there is no way
// to write to it except via a push from aaa.
//
// Being in-memory, the cache is empty after a restart until aaa pushes again
// (which happens on the next form create/update); there is no backfill.
type formsCache struct {
	mu            sync.RWMutex
	submissions   map[string]cachedSubmission
	providerForms map[string]cachedProviderForm
}

type cachedSubmission struct {
	sub        FormSubmission
	receivedAt time.Time
}

type cachedProviderForm struct {
	form       DataProviderForm
	receivedAt time.Time
}

func newFormsCache() *formsCache {
	return &formsCache{
		submissions:   make(map[string]cachedSubmission),
		providerForms: make(map[string]cachedProviderForm),
	}
}

func (c *formsCache) putSubmission(sub FormSubmission, receivedAt time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.submissions[sub.ID] = cachedSubmission{sub: sub, receivedAt: receivedAt}
}

func (c *formsCache) getSubmission(id string) *FormSubmission {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.submissions[id]
	if !ok {
		return nil
	}
	sub := entry.sub
	return &sub
}

func (c *formsCache) removeSubmission(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.submissions[id]; !ok {
		return false
	}
	delete(c.submissions, id)
	return true
}

// latestForProvider returns the most recently pushed submission that has an
// owner ip_address set and lists username in selected_providers.
func (c *formsCache) latestForProvider(username string) *FormSubmission {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var latest *cachedSubmission
	for id := range c.submissions {
		entry := c.submissions[id]
		if entry.sub.IPAddress == nil {
			continue
		}
		matches := false
		for _, p := range entry.sub.SelectedProviderList() {
			if p.Username == username {
				matches = true
				break
			}
		}
		if !matches {
			continue
		}
		if latest == nil || entry.receivedAt.After(latest.receivedAt) {
			e := entry
			latest = &e
		}
	}
	if latest == nil {
		return nil
	}
	sub := latest.sub
	return &sub
}

func (c *formsCache) putProviderForm(form DataProviderForm, receivedAt time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.providerForms[form.ID] = cachedProviderForm{form: form, receivedAt: receivedAt}
}

// formsByUsernames returns the latest pushed form per data_owner_id, for
// whichever of the given usernames have one.
func (c *formsCache) formsByUsernames(usernames []string) []DataProviderForm {
	if len(usernames) == 0 {
		return []DataProviderForm{}
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	wanted := make(map[string]bool, len(usernames))
	for _, u := range usernames {
		wanted[u] = true
	}

	latestByOwner := make(map[string]cachedProviderForm)
	for id := range c.providerForms {
		entry := c.providerForms[id]
		if entry.form.DataOwnerID == nil || !wanted[*entry.form.DataOwnerID] {
			continue
		}
		owner := *entry.form.DataOwnerID
		if current, ok := latestByOwner[owner]; !ok || entry.receivedAt.After(current.receivedAt) {
			latestByOwner[owner] = entry
		}
	}

	out := make([]DataProviderForm, 0, len(latestByOwner))
	for _, entry := range latestByOwner {
		out = append(out, entry.form)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
