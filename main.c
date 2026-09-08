#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "entropy.h"
#include "hkdf.h"
#include "aead.h"
#include "mouse_source.h"

static void print_hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

static const char *LABEL_ENC = "mouse-entropy-demo-encryption-key-v1";
static const char *LABEL_MAC = "mouse-entropy-demo-mac-key-v1";
static const char *LABEL_NONCE = "mouse-entropy-demo-nonce-v1";

int main(void) {
    printf("=== Mouse Movement Entropy Demo ===\n\n");

    /* Step 1: collect samples */
    mouse_source_init();
    EntropyPool pool;
    entropy_init(&pool);

    double x, y;
    uint64_t t_ns;
    int n = 0;
    while (mouse_source_next(&x, &y, &t_ns)) {
        entropy_add_sample(&pool, x, y, t_ns);
        n++;
    }
    printf("Collected %d samples.\n\n", n);

    /* Step 2: show the actual insight */
    double raw_bits = entropy_bits_per_byte(pool.raw_position_hist, pool.raw_position_len);
    size_t residual_len;
    const uint8_t *residual = entropy_get_residual_bytes(&pool, &residual_len);
    double residual_bits = entropy_bits_per_byte(pool.residual_hist, residual_len);

    printf("Order-0 Shannon entropy estimate (see caveat in entropy.h):\n");
    printf("  raw absolute position bytes : %.2f bits/byte over %zu bytes\n",
           raw_bits, pool.raw_position_len);
    printf("  delta/jitter residual bytes : %.2f bits/byte over %zu bytes\n",
           residual_bits, residual_len);
    if (raw_bits > residual_bits - 1.0) {
        printf(
            "\n  NOTE: these two numbers are close, and that's the actual lesson,\n"
            "  not a wash. The 'raw position' source here is a pure sine wave —\n"
            "  0%% real uncertainty; knowing the sample index tells you the exact\n"
            "  next byte. But its values sweep past 256 repeatedly, so the byte\n"
            "  histogram LOOKS well-spread and scores high on this metric anyway.\n"
            "  A naive byte-distribution entropy check cannot tell a genuinely\n"
            "  unpredictable source from a wide-ranging deterministic formula\n"
            "  that merely wraps around a lot. That's exactly why real entropy\n"
            "  assessment needs either a physical unpredictability argument\n"
            "  (this demo's actual claim rests on /dev/urandom jitter, not on\n"
            "  this histogram number) or standardized suites like NIST SP\n"
            "  800-90B — not a single order-0 histogram like the one above.\n");
    }
    printf("  -> only the residual bytes get extracted below, and the actual\n"
           "     entropy claim rests on the jitter source, not this metric.\n\n");

    /* Step 3: extract raw entropy into a uniform seed */
    uint8_t prk[32];
    hkdf_extract(NULL, 0, residual, residual_len, prk);
    printf("Extracted PRK (HKDF-Extract over the residual bytes):\n  ");
    print_hex(prk, 32);

    /* Step 4: expand into independent, purpose-labeled keys */
    uint8_t key_enc[32], key_mac[32], nonce_material[16];
    hkdf_expand(prk, (const uint8_t *)LABEL_ENC, strlen(LABEL_ENC), key_enc, 32);
    hkdf_expand(prk, (const uint8_t *)LABEL_MAC, strlen(LABEL_MAC), key_mac, 32);
    hkdf_expand(prk, (const uint8_t *)LABEL_NONCE, strlen(LABEL_NONCE), nonce_material, 12);
    printf("\nDerived encryption key : "); print_hex(key_enc, 32);
    printf("Derived MAC key        : "); print_hex(key_mac, 32);
    printf("Derived nonce          : "); print_hex(nonce_material, 12);

    /* Step 5: actually encrypt something with vetted, tested primitives */
    const char *message = "Patient note (demo only, not real PHI): BP 118/76, HR 72.";
    size_t msg_len = strlen(message);
    assert(msg_len <= 256); /* fixed-size demo buffers below assume this */
    uint8_t ciphertext[256], tag[32];
    aead_encrypt(key_enc, key_mac, nonce_material, (const uint8_t *)message, msg_len,
                 ciphertext, tag);

    printf("\nPlaintext : %s\n", message);
    printf("Ciphertext: "); print_hex(ciphertext, msg_len);
    printf("Tag       : "); print_hex(tag, 32);

    /* Step 6: decrypt and verify round-trip */
    uint8_t decrypted[256] = {0};
    int ok = aead_decrypt(key_enc, key_mac, nonce_material, ciphertext, msg_len, tag, decrypted);
    printf("\nDecrypt with correct tag -> %s\n", ok ? "verified OK" : "FAILED");
    if (ok) printf("Recovered: %s\n", decrypted);

    /* Step 7: demonstrate tamper detection */
    uint8_t tampered[256];
    memcpy(tampered, ciphertext, msg_len);
    tampered[0] ^= 0x01; /* flip one bit */
    uint8_t decrypted2[256] = {0};
    int ok2 = aead_decrypt(key_enc, key_mac, nonce_material, tampered, msg_len, tag, decrypted2);
    printf("\nDecrypt after flipping one ciphertext bit -> %s\n",
           ok2 ? "verified OK (BUG if you see this)" : "correctly rejected");

    return 0;
}
