CREATE TABLE "assessments" (
	"id" text PRIMARY KEY NOT NULL,
	"owner_id" text NOT NULL,
	"name" text NOT NULL,
	"client" text,
	"scope" jsonb NOT NULL,
	"phase" text NOT NULL,
	"status" text NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	"updated_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "assets" (
	"id" text NOT NULL,
	"assessment_id" text NOT NULL,
	"kind" text NOT NULL,
	"name" text NOT NULL,
	"host" text,
	"port" integer,
	"url" text,
	"in_scope" boolean DEFAULT true NOT NULL,
	"tags" jsonb DEFAULT '[]'::jsonb NOT NULL,
	CONSTRAINT "assets_pk" PRIMARY KEY("assessment_id","id")
);
--> statement-breakpoint
CREATE TABLE "audit_log" (
	"id" serial PRIMARY KEY NOT NULL,
	"assessment_id" text NOT NULL,
	"finding_id" text,
	"actor" text NOT NULL,
	"action" text NOT NULL,
	"field" text NOT NULL,
	"from_value" text,
	"to_value" text,
	"reason" text,
	"at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "evidence" (
	"id" text PRIMARY KEY NOT NULL,
	"finding_id" text NOT NULL,
	"kind" text NOT NULL,
	"title" text,
	"content" text NOT NULL,
	"redacted" boolean DEFAULT false NOT NULL,
	"captured_at" timestamp with time zone,
	"source" jsonb
);
--> statement-breakpoint
CREATE TABLE "findings" (
	"id" text PRIMARY KEY NOT NULL,
	"assessment_id" text NOT NULL,
	"asset_id" text NOT NULL,
	"title" text NOT NULL,
	"scope" text NOT NULL,
	"impact" text NOT NULL,
	"risk" jsonb NOT NULL,
	"severity" text NOT NULL,
	"fix" text NOT NULL,
	"retest" jsonb,
	"phase" text NOT NULL,
	"status" text NOT NULL,
	"false_positive_reason" text,
	"sources" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"mappings" jsonb NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	"updated_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "imports" (
	"id" text PRIMARY KEY NOT NULL,
	"assessment_id" text NOT NULL,
	"actor" text NOT NULL,
	"tool" text NOT NULL,
	"filename" text,
	"parsed" integer NOT NULL,
	"created" integer NOT NULL,
	"merged" integer NOT NULL,
	"assets_created" integer NOT NULL,
	"warnings" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
ALTER TABLE "assets" ADD CONSTRAINT "assets_assessment_id_assessments_id_fk" FOREIGN KEY ("assessment_id") REFERENCES "public"."assessments"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_log" ADD CONSTRAINT "audit_log_assessment_id_assessments_id_fk" FOREIGN KEY ("assessment_id") REFERENCES "public"."assessments"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_log" ADD CONSTRAINT "audit_log_finding_id_findings_id_fk" FOREIGN KEY ("finding_id") REFERENCES "public"."findings"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "evidence" ADD CONSTRAINT "evidence_finding_id_findings_id_fk" FOREIGN KEY ("finding_id") REFERENCES "public"."findings"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "findings" ADD CONSTRAINT "findings_assessment_id_assessments_id_fk" FOREIGN KEY ("assessment_id") REFERENCES "public"."assessments"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "findings" ADD CONSTRAINT "findings_asset_in_assessment_fk" FOREIGN KEY ("asset_id","assessment_id") REFERENCES "public"."assets"("id","assessment_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "imports" ADD CONSTRAINT "imports_assessment_id_assessments_id_fk" FOREIGN KEY ("assessment_id") REFERENCES "public"."assessments"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "assessments_owner_idx" ON "assessments" USING btree ("owner_id");--> statement-breakpoint
CREATE INDEX "audit_assessment_idx" ON "audit_log" USING btree ("assessment_id","id");--> statement-breakpoint
CREATE INDEX "audit_finding_idx" ON "audit_log" USING btree ("finding_id");--> statement-breakpoint
CREATE INDEX "evidence_finding_idx" ON "evidence" USING btree ("finding_id");--> statement-breakpoint
CREATE INDEX "findings_assessment_idx" ON "findings" USING btree ("assessment_id");--> statement-breakpoint
CREATE INDEX "findings_asset_idx" ON "findings" USING btree ("assessment_id","asset_id");--> statement-breakpoint
CREATE INDEX "findings_severity_idx" ON "findings" USING btree ("assessment_id","severity");--> statement-breakpoint
CREATE INDEX "imports_assessment_idx" ON "imports" USING btree ("assessment_id");