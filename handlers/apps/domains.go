package apps

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/neoworks/auth/domainproof"
	"github.com/neoworks/auth/handlers/respond"
	"github.com/neoworks/auth/ownership"
	"github.com/neoworks/auth/storage/database"
)

type addDomainRequest struct {
	Domain string `json:"domain"`
	Method string `json:"method"`
}

func (h *Handler) listDomains(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.ownerOf(w, r)
	if !ok {
		return
	}
	domains, err := h.store.ListDomains(r.Context(), owner.handle)
	if err != nil {
		respond.StoreError(w, "listDomains", err)
		return
	}
	respond.JSON(w, http.StatusOK, map[string]any{"domains": domains})
}

func (h *Handler) addDomain(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.ownerOf(w, r)
	if !ok || !h.allowed(w, r, owner, ownership.DomainsManage) {
		return
	}
	var request addDomainRequest
	if !respond.Decode(w, r, &request, maxRequestBody) {
		return
	}
	domain, ok := domainproof.NormalizeDomain(request.Domain)
	if !ok {
		writeFieldError(w, "addDomain", invalidField("domain", "enter a domain such as example.com, without scheme, port or path"))
		return
	}
	if request.Method != database.DomainMethodDNS && request.Method != database.DomainMethodWellKnown {
		writeFieldError(w, "addDomain", invalidField("method", "method must be dns or wellKnown"))
		return
	}
	token, err := domainproof.NewToken()
	if err != nil {
		respond.StoreError(w, "newToken", err)
		return
	}
	added, err := h.store.AddDomain(r.Context(), owner.handle, domain, request.Method, token)
	if errors.Is(err, database.ErrDomainExists) {
		respond.JSON(w, http.StatusConflict, map[string]string{"error": "domain_exists", "field": "domain", "message": domain + " was already added"})
		return
	}
	if err != nil {
		respond.StoreError(w, "addDomain", err)
		return
	}
	h.audit(r, owner, database.AuditDomainAdded, domainTarget(domain), map[string]any{"method": request.Method})
	respond.JSON(w, http.StatusCreated, added)
}

func domainTarget(domain string) database.AuditTarget {
	return database.AuditTarget{Kind: "domain", ID: domain, Label: domain}
}

// verifyDomain checks the proof now. A failed check is not an error: the
// response is the domain, still unverified.
func (h *Handler) verifyDomain(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.ownerOf(w, r)
	if !ok || !h.allowed(w, r, owner, ownership.DomainsManage) {
		return
	}
	domain, err := h.store.GetDomain(r.Context(), owner.handle, chi.URLParam(r, "domain"))
	if err != nil {
		respond.StoreError(w, "getDomain", err)
		return
	}
	check, err := h.verifier.Check(r.Context(), owner.handle, *domain)
	if errors.Is(err, database.ErrDomainTaken) {
		respond.JSON(w, http.StatusConflict, map[string]string{"error": "domain_taken", "message": domain.Domain + " is verified by another owner"})
		return
	}
	if err != nil {
		respond.StoreError(w, "checkDomain", err)
		return
	}
	h.auditCheck(r, owner, *domain, check)
	respond.JSON(w, http.StatusOK, check.Domain)
}

func (h *Handler) auditCheck(r *http.Request, a *acting, before database.OwnerDomain, check *database.DomainCheck) {
	switch {
	case check.Domain.Verified && !before.Verified:
		h.audit(r, a, database.AuditDomainVerified, domainTarget(before.Domain), map[string]any{"method": before.Method})
	case check.Revoked:
		h.audit(r, a, database.AuditDomainRevoked, domainTarget(before.Domain), map[string]any{"method": before.Method})
	}
}

func (h *Handler) removeDomain(w http.ResponseWriter, r *http.Request) {
	owner, ok := h.ownerOf(w, r)
	if !ok || !h.allowed(w, r, owner, ownership.DomainsManage) {
		return
	}
	domain := chi.URLParam(r, "domain")
	wasVerified, err := h.store.RemoveDomain(r.Context(), owner.handle, domain)
	if err != nil {
		respond.StoreError(w, "removeDomain", err)
		return
	}
	if wasVerified {
		h.refreshApps(r, owner.handle)
	}
	h.audit(r, owner, database.AuditDomainRemoved, domainTarget(domain), map[string]any{"wasVerified": wasVerified})
	w.WriteHeader(http.StatusNoContent)
}

// refreshApps re-evaluates the verification of the owner's apps; a failure is
// logged, since the domain change already happened.
func (h *Handler) refreshApps(r *http.Request, handle string) {
	if _, err := h.store.RefreshOwnerVerification(r.Context(), handle); err != nil {
		slog.Error("refresh app verification", "owner", handle, "error", err)
	}
}
