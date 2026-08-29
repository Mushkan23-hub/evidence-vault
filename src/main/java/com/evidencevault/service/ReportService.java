package com.evidencevault.service;

import com.evidencevault.model.AuditAction;
import com.evidencevault.model.AuditLogEntry;
import com.evidencevault.model.Case;
import com.evidencevault.model.EvidenceFile;
import com.evidencevault.repository.AuditLogRepository;
import com.evidencevault.repository.EvidenceFileRepository;
import lombok.RequiredArgsConstructor;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.format.DateTimeFormatter;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ReportService {

    private static final float MARGIN = 50;
    private static final float PAGE_HEIGHT = PDRectangle.A4.getHeight();
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss 'UTC'").withZone(ZoneOffset.UTC);

    private final CaseService caseService;
    private final EvidenceFileRepository evidenceFileRepository;
    private final AuditLogRepository auditLogRepository;
    private final AuditLogService auditLogService;

    public byte[] generateCaseReport(String username, UUID caseId) {
        Case c = caseService.assertAccess(username, caseId); // enforce case access before exposing evidence/audit data
        List<EvidenceFile> evidenceFiles = evidenceFileRepository.findByEvidenceCaseId(caseId);
        List<AuditLogEntry> auditEntries = auditLogRepository.findByRelatedCaseIdOrderBySequenceNumberAsc(caseId);

        try (PDDocument doc = new PDDocument()) {
            Writer w = new Writer(doc);

            w.heading("CHAIN OF CUSTODY REPORT");
            w.gap(4);
            w.line("Generated " + FMT.format(java.time.Instant.now()) + " by " + username, w.helvetica, 9);
            w.gap(14);

            w.subheading("Case Details");
            w.line("Case Number:  " + c.getCaseNumber());
            w.line("Title:        " + c.getTitle());
            w.line("Status:       " + c.getStatus());
            w.line("Created By:   " + c.getCreatedBy().getUsername());
            w.line("Created At:   " + FMT.format(c.getCreatedAt()));
            if (c.getDescription() != null && !c.getDescription().isBlank()) {
                w.line("Description:  " + c.getDescription());
            }
            w.gap(14);

            w.subheading("Evidence Files (" + evidenceFiles.size() + ")");
            if (evidenceFiles.isEmpty()) {
                w.line("No evidence has been uploaded to this case.");
            }
            for (EvidenceFile f : evidenceFiles) {
                w.gap(6);
                w.line("- " + f.getOriginalFilename(), w.helveticaBold, 10);
                w.line("  SHA-256: " + f.getSha256Hash(), w.helvetica, 8);
                w.line("  Uploaded by " + f.getUploadedBy().getUsername() + " at " + FMT.format(f.getUploadedAt())
                        + " (" + f.getOriginalSizeBytes() + " bytes)", w.helvetica, 8);
                String verifyStatus = f.getLastVerificationPassed() == null ? "not yet verified"
                        : (f.getLastVerificationPassed() ? "PASSED" : "FAILED");
                w.line("  Last integrity check: " + verifyStatus
                        + (f.getLastVerifiedAt() != null ? " at " + FMT.format(f.getLastVerifiedAt()) : ""),
                        w.helvetica, 8);
            }
            w.gap(14);

            w.subheading("Audit Trail for This Case (" + auditEntries.size() + " entries)");
            for (AuditLogEntry e : auditEntries) {
                w.gap(4);
                w.line("#" + e.getSequenceNumber() + "  " + e.getAction() + "  -  " + e.getActorUsername(),
                        w.helveticaBold, 9);
                w.line("  " + FMT.format(e.getTimestamp()) + (e.getDetails() != null ? "  -  " + e.getDetails() : ""),
                        w.helvetica, 8);
                w.line("  entryHash: " + shortHash(e.getEntryHash()), w.helvetica, 7);
            }

            w.close();

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            doc.save(out);

            auditLogService.record(username, AuditAction.REPORT_GENERATED, caseId, null,
                    "Chain-of-custody PDF report generated for case " + c.getCaseNumber());

            return out.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to generate PDF report", e);
        }
    }

    private String shortHash(String h) {
        if (h == null || h.length() < 16) return h;
        return h.substring(0, 10) + "..." + h.substring(h.length() - 8);
    }

    /** Small helper that tracks vertical position and starts new pages as content overflows. */
    private static class Writer {
        private final PDDocument doc;
        private PDPageContentStream cs;
        private float y;

        final PDFont helvetica;
        final PDFont helveticaBold;

        Writer(PDDocument doc) throws IOException {
            this.doc = doc;
            this.helvetica = new PDType1Font(Standard14Fonts.FontName.HELVETICA);
            this.helveticaBold = new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD);
            newPage();
        }

        private void newPage() throws IOException {
            if (cs != null) cs.close();
            PDPage page = new PDPage(PDRectangle.A4);
            doc.addPage(page);
            cs = new PDPageContentStream(doc, page);
            y = PAGE_HEIGHT - MARGIN;
        }

        void heading(String text) throws IOException {
            ensureSpace(24);
            writeText(text, helveticaBold, 16);
            y -= 22;
        }

        void subheading(String text) throws IOException {
            ensureSpace(18);
            writeText(text, helveticaBold, 12);
            y -= 16;
        }

        void line(String text) throws IOException {
            line(text, helvetica, 10);
        }

        void line(String text, PDFont font, int size) throws IOException {
            ensureSpace(size + 4);
            writeText(text, font, size);
            y -= (size + 4);
        }

        void gap(float amount) {
            y -= amount;
        }

        private void ensureSpace(float needed) throws IOException {
            if (y - needed < MARGIN) {
                newPage();
            }
        }

        private void writeText(String text, PDFont font, int size) throws IOException {
            // Guard against characters the standard 14 fonts can't encode
            String safe = text.replaceAll("[^\\x00-\\xFF]", "?");
            if (safe.length() > 110) safe = safe.substring(0, 110);
            cs.beginText();
            cs.setFont(font, size);
            cs.newLineAtOffset(MARGIN, y);
            cs.showText(safe);
            cs.endText();
        }

        void close() throws IOException {
            if (cs != null) cs.close();
        }
    }
}
