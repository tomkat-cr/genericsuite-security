-- project-insights.sql
--
-- CREATE TABLE for the flat projection this skill writes to
-- insights/insights-table.json and insights/insights-table.csv.
--
-- This DDL is provided for anyone who wants to load that projection into
-- their own database. The skill NEVER runs this file and NEVER writes to a
-- database itself -- every output lands under ./insights on disk. Column
-- names and order match policy/weakness.json's `table_columns` exactly, so
-- a future database writer is an additive step over an existing row shape,
-- not a redesign. See SKILL.md's "Output" section.

CREATE TABLE IF NOT EXISTS project_insights (
    id                          bigserial PRIMARY KEY,

    -- Identity
    project_slug                text NOT NULL,
    name                         text,
    repo_url                     text,
    repo_source_field            text,
    path                         text,
    branch                       text,
    head_sha                     text,

    -- Repository signals
    stars                        integer,
    forks                        integer,
    contributors                 integer,
    commit_count                 integer,
    code_loc                     integer,
    license                      text,
    primary_language             text,
    project_type                 text,
    uses_orm                     boolean,
    orm_or_db_layer              text,

    -- Readiness axis (analyze agent)
    maturity_score               integer,
    production_readiness_score   integer,
    code_organization_score      integer,
    maintainability_score        integer,
    readiness                    text,

    -- Security axis (security agent + re-audit)
    security_risk                text,
    previous_risk                text,
    open_findings                integer,
    resolved_findings            integer,
    red_flags_count              integer,

    -- Gate outcome
    blocked                      boolean,

    -- Timing
    audited_at                   timestamptz,
    reaudited_at                 timestamptz,

    created_at                   timestamptz NOT NULL DEFAULT now(),
    updated_at                   timestamptz NOT NULL DEFAULT now(),

    UNIQUE (project_slug)
);

COMMENT ON TABLE project_insights IS
    'Flat projection of a project-weakness-analysis run. One row per project, '
    'matching insights/insights-table.json. Populated by an external loader, '
    'never by the skill itself.';
