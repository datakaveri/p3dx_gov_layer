// Package grpcsrv implements the gRPC GovernanceService on port 50052,
// reproducing src/grpc/governance.server.js: SubmitForm, GetForm, GetAllForms,
// DeleteForm backed by the same PostgreSQL data layer.
package grpcsrv

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/db"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/govpb"
)

// GovernanceServer implements govpb.GovernanceServiceServer.
type GovernanceServer struct {
	govpb.UnimplementedGovernanceServiceServer
	db *db.DB
}

// SubmitForm stores a form submission. Mirrors submitForm().
func (g *GovernanceServer) SubmitForm(ctx context.Context, req *govpb.FormSubmission) (*govpb.SubmissionResponse, error) {
	log.Printf("[gRPC] SubmitForm called with: %v", req)

	components, _ := json.Marshal(req.GetComponents())
	in := &db.FormInput{
		FormID:           req.GetFormId(),
		RequestedBy:      req.GetRequestedBy(),
		OutputOwnerID:    req.GetOutputOwnerId(),
		NumServerRounds:  db.NewFlexFloat(float64(req.GetNumServerRounds())),
		FractionEvaluate: db.NewFlexFloat(req.GetFractionEvaluate()),
		LocalEpochs:      db.NewFlexFloat(float64(req.GetLocalEpochs())),
		LearningRate:     db.NewFlexFloat(req.GetLearningRate()),
		BatchSize:        db.NewFlexFloat(float64(req.GetBatchSize())),
		Model:            strPtr(req.GetModel()),
		Framework:        strPtr(req.GetFramework()),
		Components:       components,
		RequestedAt:      strPtrOrNil(req.GetRequestedAt()),
		FilledAt:         strPtrOrNil(req.GetFilledAt()),
	}

	submissionID, err := g.db.StoreFormSubmission(ctx, in)
	if err != nil {
		log.Printf("[gRPC] Error in SubmitForm: %v", err)
		return nil, err
	}
	log.Printf("[gRPC] Form stored successfully with ID: %s", submissionID)
	return &govpb.SubmissionResponse{
		Success:      true,
		Message:      "Form submitted successfully",
		SubmissionId: submissionID,
	}, nil
}

// GetForm retrieves a form by id. Mirrors getForm().
func (g *GovernanceServer) GetForm(ctx context.Context, req *govpb.GetFormRequest) (*govpb.FormSubmission, error) {
	log.Printf("[gRPC] GetForm called with ID: %s", req.GetId())
	form, err := g.db.GetFormSubmissionByID(ctx, req.GetId())
	if err != nil {
		log.Printf("[gRPC] Error in GetForm: %v", err)
		return nil, err
	}
	if form == nil {
		return nil, status.Error(codes.NotFound, "Form not found")
	}
	log.Println("[gRPC] Form retrieved successfully")
	return formToProto(form), nil
}

// GetAllForms retrieves every form. Mirrors getAllForms().
func (g *GovernanceServer) GetAllForms(ctx context.Context, _ *govpb.GetAllFormsRequest) (*govpb.GetAllFormsResponse, error) {
	log.Println("[gRPC] GetAllForms called")
	forms, err := g.db.GetAllFormSubmissions(ctx)
	if err != nil {
		log.Printf("[gRPC] Error in GetAllForms: %v", err)
		return nil, err
	}
	log.Printf("[gRPC] Retrieved %d forms", len(forms))
	out := make([]*govpb.FormSubmission, 0, len(forms))
	for i := range forms {
		out = append(out, formToProto(&forms[i]))
	}
	return &govpb.GetAllFormsResponse{Forms: out, TotalCount: int32(len(forms))}, nil
}

// DeleteForm deletes a form by id. Mirrors deleteForm() (always reports success
// on a clean run, matching the Node handler which does not check the row count).
func (g *GovernanceServer) DeleteForm(ctx context.Context, req *govpb.DeleteFormRequest) (*govpb.DeleteResponse, error) {
	log.Printf("[gRPC] DeleteForm called with ID: %s", req.GetId())
	if _, err := g.db.DeleteFormSubmission(ctx, req.GetId()); err != nil {
		log.Printf("[gRPC] Error in DeleteForm: %v", err)
		return nil, err
	}
	log.Println("[gRPC] Form deleted successfully")
	return &govpb.DeleteResponse{Success: true, Message: "Form deleted successfully"}, nil
}

// formToProto maps a DB row to the proto message (camelCase fields), formatting
// timestamps as ISO strings. updated_at has no column, so it is left empty (the
// Node code mapped form.updated_at, which was undefined).
func formToProto(f *db.FormSubmission) *govpb.FormSubmission {
	components := map[string]string{}
	if len(f.Components) > 0 {
		_ = json.Unmarshal(f.Components, &components)
	}
	return &govpb.FormSubmission{
		Id:               f.ID,
		FormId:           f.FormID,
		RequestedBy:      f.RequestedBy,
		OutputOwnerId:    f.OutputOwnerID,
		NumServerRounds:  deref32(f.NumServerRounds),
		FractionEvaluate: f.FractionEvaluate.F64(),
		LocalEpochs:      deref32(f.LocalEpochs),
		LearningRate:     f.LearningRate.F64(),
		BatchSize:        deref32(f.BatchSize),
		Model:            derefS(f.Model),
		Framework:        derefS(f.Framework),
		Components:       components,
		Filled:           f.Filled != nil && *f.Filled,
		RequestedAt:      isoOrEmpty(f.RequestedAt),
		FilledAt:         isoOrEmpty(f.FilledAt),
		CreatedAt:        isoOrEmpty(f.CreatedAt),
	}
}

// Start launches the gRPC server on the given port and returns it (already
// serving in a background goroutine). Mirrors startGrpcServer().
func Start(database *db.DB, port string) (*grpc.Server, error) {
	lis, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		log.Printf("[gRPC] Failed to start server: %v", err)
		return nil, err
	}
	srv := grpc.NewServer()
	govpb.RegisterGovernanceServiceServer(srv, &GovernanceServer{db: database})
	go func() {
		log.Printf("[gRPC] Server running on port %s", port)
		if err := srv.Serve(lis); err != nil {
			log.Printf("[gRPC] Serve stopped: %v", err)
		}
	}()
	return srv, nil
}

func strPtr(s string) *string { return &s }

func strPtrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func deref32(p *int32) int32 {
	if p == nil {
		return 0
	}
	return *p
}

func derefS(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func isoOrEmpty(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04:05.000Z07:00")
}
