-- CreateEnum
CREATE TYPE "DocumentCategory" AS ENUM ('TAX_DOCUMENT', 'PROJECT_REPORT', 'STATEMENT');

-- CreateEnum
CREATE TYPE "DocumentStatus" AS ENUM ('PENDING_REVIEW', 'PUBLISHED', 'ARCHIVED');

-- CreateTable
CREATE TABLE "PortalUser" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "role" TEXT NOT NULL,
    "lastSyncedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PortalUser_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Document" (
    "id" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "category" "DocumentCategory" NOT NULL,
    "year" INTEGER NOT NULL,
    "projectName" TEXT,
    "status" "DocumentStatus" NOT NULL DEFAULT 'PENDING_REVIEW',
    "dropboxFolderPath" TEXT,
    "currentVersionId" TEXT,
    "createdByUserId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Document_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DocumentVersion" (
    "id" TEXT NOT NULL,
    "documentId" TEXT NOT NULL,
    "versionNumber" INTEGER NOT NULL,
    "fileName" TEXT NOT NULL,
    "dropboxFileId" TEXT,
    "dropboxRev" TEXT,
    "sizeBytes" INTEGER,
    "checksumSha256" TEXT,
    "uploadedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "supersededAt" TIMESTAMP(3),

    CONSTRAINT "DocumentVersion_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DocumentAssignment" (
    "id" TEXT NOT NULL,
    "documentId" TEXT NOT NULL,
    "investorUserId" TEXT NOT NULL,
    "assignedById" TEXT,
    "assignedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DocumentAssignment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditLogEntry" (
    "id" TEXT NOT NULL,
    "actorUserId" TEXT,
    "actorEmail" TEXT,
    "action" TEXT NOT NULL,
    "targetType" TEXT,
    "targetId" TEXT,
    "metadata" JSONB,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuditLogEntry_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "PortalUser_email_key" ON "PortalUser"("email");

-- CreateIndex
CREATE INDEX "PortalUser_role_idx" ON "PortalUser"("role");

-- CreateIndex
CREATE UNIQUE INDEX "Document_currentVersionId_key" ON "Document"("currentVersionId");

-- CreateIndex
CREATE INDEX "Document_category_year_idx" ON "Document"("category", "year");

-- CreateIndex
CREATE INDEX "Document_status_idx" ON "Document"("status");

-- CreateIndex
CREATE UNIQUE INDEX "DocumentVersion_documentId_versionNumber_key" ON "DocumentVersion"("documentId", "versionNumber");

-- CreateIndex
CREATE INDEX "DocumentAssignment_investorUserId_idx" ON "DocumentAssignment"("investorUserId");

-- CreateIndex
CREATE UNIQUE INDEX "DocumentAssignment_documentId_investorUserId_key" ON "DocumentAssignment"("documentId", "investorUserId");

-- CreateIndex
CREATE INDEX "AuditLogEntry_createdAt_idx" ON "AuditLogEntry"("createdAt");

-- CreateIndex
CREATE INDEX "AuditLogEntry_actorUserId_idx" ON "AuditLogEntry"("actorUserId");

-- CreateIndex
CREATE INDEX "AuditLogEntry_action_idx" ON "AuditLogEntry"("action");

-- AddForeignKey
ALTER TABLE "Document" ADD CONSTRAINT "Document_createdByUserId_fkey" FOREIGN KEY ("createdByUserId") REFERENCES "PortalUser"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Document" ADD CONSTRAINT "Document_currentVersionId_fkey" FOREIGN KEY ("currentVersionId") REFERENCES "DocumentVersion"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DocumentVersion" ADD CONSTRAINT "DocumentVersion_documentId_fkey" FOREIGN KEY ("documentId") REFERENCES "Document"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DocumentAssignment" ADD CONSTRAINT "DocumentAssignment_documentId_fkey" FOREIGN KEY ("documentId") REFERENCES "Document"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DocumentAssignment" ADD CONSTRAINT "DocumentAssignment_investorUserId_fkey" FOREIGN KEY ("investorUserId") REFERENCES "PortalUser"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DocumentAssignment" ADD CONSTRAINT "DocumentAssignment_assignedById_fkey" FOREIGN KEY ("assignedById") REFERENCES "PortalUser"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuditLogEntry" ADD CONSTRAINT "AuditLogEntry_actorUserId_fkey" FOREIGN KEY ("actorUserId") REFERENCES "PortalUser"("id") ON DELETE SET NULL ON UPDATE CASCADE;
