package com.evidencevault.config;

import com.evidencevault.model.Challenge;
import com.evidencevault.model.ChallengeCategory;
import com.evidencevault.model.ChallengeDifficulty;
import com.evidencevault.repository.ChallengeRepository;
import com.evidencevault.service.HashService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class ChallengeSeeder implements CommandLineRunner {

    private final ChallengeRepository challengeRepository;
    private final HashService hashService;

    @Override
    public void run(String... args) {
        seed("Hidden in Plain Sight",
                "This file looks like meaningless binary noise, but somewhere inside it is a short piece of "
                        + "readable text. Download the artifact and use the Extract Strings tool to find it. "
                        + "Submit the flag exactly as you find it.",
                ChallengeCategory.STRINGS, ChallengeDifficulty.EASY, 100,
                "FLAG{str1ngs_dont_l1e}",
                "mystery_file.bin",
                "OQyMfXJHNCzYEA8vb3cNZdZw5Y4DUdiujk9urDQvwjG3sIcW6z/BKJa5YiMXdJQodzPCjui6U721a4gkV31T7MKKcKYcdRChzYkhbKFs/8pGTEFHe3N0cjFuZ3NfZG9udF9sMWV96kmHR36G28y5cEb8Lhg4TlHYIMXD74AFOoiuOZbeUOgBhls2mGVOv1IApfoJObmdeh17KCv4I0BB81SH2Gxmn8y/4Oc9fnMgrQp1cAMkHnU=");

        seed("Wolf in Sheep's Clothing",
                "This file is named 'holiday_photo.txt' but something about it doesn't add up. Use the "
                        + "Detect File Type tool to find out what it actually is. Submit the flag as "
                        + "FLAG{<detected_type_in_lowercase_with_underscores_instead_of_spaces>} - for example "
                        + "if the detected type were \"Cat Picture\" you'd submit FLAG{cat_picture}.",
                ChallengeCategory.FILE_ANALYSIS, ChallengeDifficulty.EASY, 100,
                "FLAG{png_image}",
                "holiday_photo.txt",
                "iVBORw0KGgoiEKkkeY74bUPyfPLQYTAx3LXY0u8bMh/OrTd/YmHlR9hdjux/JuIyGQcveVXQ+PZtzR5UwgHHh+iS2PlPYZdvHR+gHRn0UB0pXyMieM49fhQp1qGFaKB6h8pDmeqhJQTqMyVth0OyI329kVDgmgSZNUSHOzZPi5A=");

        seed("Hex Needle",
                "Somewhere in the first 512 bytes of this file's hex dump, a short message hides in plain "
                        + "sight in the ASCII column on the right. Use the Hex Dump tool and read carefully. "
                        + "Submit the flag exactly as you find it.",
                ChallengeCategory.HEX_DUMP, ChallengeDifficulty.MEDIUM, 150,
                "FLAG{h3x_r3ading_sk1lls}",
                "raw_dump.bin",
                "a69oh/qAGi/YjRYBqkKGUuLaBDkmTBK9S9xBFZ26FLdrfzS10E95U1rTDFuq0n+IUTfDE/BxZuuznHRyDGLMqI4jjrPMqQ47hVuHEzfesKDfO8VhghbfAGS63COpoD+ZntGnzpdBYtfCWZrPAJuSa9yk7uLibfJWK5GrL3iec2VLDBd98yXp1GPE/cx8SwI22XBa7Rl/RkxBR3toM3hfcjNhZGluZ19zazFsbHN9PulE7aLi2uRR8+aEfo34eozhJ5J4i6ujKUZNdsRObSDU0Knu1B9p18cKwvQDtJjH1nD5cIvf+A7HrM9U70ENyQ0q20XsXRmFwqds6Keswo7XgSnwCRqzciMUD35mCk56QPI6b+6DvFU6U583DZ/Ay2UmfDSaPRWx270jrgbX+jbduetO3lqK9+7fiaV9LI7mfO3CrA79");

        seed("The Chain Never Lies",
                "Below is a snippet from a hypothetical audit chain (illustrative, not live data from this "
                        + "system). Each entry's previousHash should exactly match the entryHash of the entry "
                        + "right before it. One entry in this chain breaks that rule - find it.\n\n"
                        + "Seq 0: entryHash=aaa111...  previousHash=000000...\n"
                        + "Seq 1: entryHash=bbb222...  previousHash=aaa111...\n"
                        + "Seq 2: entryHash=ccc333...  previousHash=bbb222...\n"
                        + "Seq 3: entryHash=ddd444...  previousHash=zzz999...\n"
                        + "Seq 4: entryHash=eee555...  previousHash=ddd444...\n\n"
                        + "At which sequence number does the chain break? Submit as FLAG{seq_<number>}.",
                ChallengeCategory.AUDIT_LOG, ChallengeDifficulty.MEDIUM, 150,
                "FLAG{seq_3}", null, null);

        seed("Hash It Out",
                "Compute the SHA-256 hash of the exact ASCII string \"evidence\" (no quotes, no surrounding "
                        + "whitespace, no trailing newline). You can use any tool: a terminal (echo -n \"evidence\" "
                        + "| sha256sum on Linux/Kali), an online calculator, or write a one-line script. Submit "
                        + "the flag as FLAG{<the_resulting_hex_hash_in_lowercase>}.",
                ChallengeCategory.HASHING, ChallengeDifficulty.EASY, 100,
                "FLAG{" + hashService.sha256Hex("evidence") + "}", null, null);
    }

    private void seed(String title, String description, ChallengeCategory category, ChallengeDifficulty difficulty,
                       int points, String flagText, String artifactFilename, String artifactBase64) {
        if (challengeRepository.existsByTitle(title)) {
            return;
        }
        Challenge c = Challenge.builder()
                .title(title)
                .description(description)
                .category(category)
                .difficulty(difficulty)
                .points(points)
                .flagHash(hashService.sha256Hex(flagText.trim()))
                .artifactFilename(artifactFilename)
                .artifactBase64(artifactBase64)
                .build();
        challengeRepository.save(c);
    }
}
