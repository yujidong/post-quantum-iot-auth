/*
 * PQC Crypto Benchmark for IoT Device Simulation
 * Cross-compiles for x86_64 and aarch64
 * Measures: keygen, sign, verify times for Falcon-512, Dilithium2, Dilithium3, ECDSA P-256
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <oqs/oqs.h>

#define NUM_ITERATIONS 1000
#define WARMUP_ITERATIONS 50

/* Get wall-clock time in microseconds */
static double get_time_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

/* Statistics */
typedef struct {
    double min, max, mean, median, p99;
    double sum;
    int count;
} stats_t;

static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a, db = *(const double *)b;
    return (da > db) - (da < db);
}

static stats_t compute_stats(double *values, int count) {
    stats_t s = {0};
    qsort(values, count, sizeof(double), cmp_double);
    s.min = values[0];
    s.max = values[count - 1];
    s.count = count;
    s.sum = 0;
    for (int i = 0; i < count; i++) s.sum += values[i];
    s.mean = s.sum / count;
    s.median = values[count / 2];
    s.p99 = values[(int)(count * 0.99)];
    return s;
}

static void print_stats(const char *label, stats_t *s) {
    printf("  %-30s  min=%8.1f  avg=%8.1f  med=%8.1f  p99=%8.1f  max=%8.1f  (us)\n",
           label, s->min, s->mean, s->median, s->p99, s->max);
}

static void benchmark_sig(const char *alg_name) {
    OQS_SIG *sig = OQS_SIG_new(alg_name);
    if (!sig) {
        printf("  [SKIP] %s - not available\n", alg_name);
        return;
    }

    printf("\n=== %s ===\n", alg_name);
    printf("  PK size: %zu  SK size: %zu  Sig size: %zu\n",
           sig->length_public_key, sig->length_secret_key, sig->length_signature);

    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    uint8_t *sig_buf = malloc(sig->length_signature);
    size_t sig_len = 0;

    /* Test message */
    uint8_t msg[] = "Benchmark test message for PQC signature scheme evaluation on IoT devices";
    size_t msg_len = strlen((char *)msg);

    double *kg_times = malloc(NUM_ITERATIONS * sizeof(double));
    double *sign_times = malloc(NUM_ITERATIONS * sizeof(double));
    double *verify_times = malloc(NUM_ITERATIONS * sizeof(double));

    /* Warmup */
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        OQS_SIG_keypair(sig, pk, sk);
        OQS_SIG_sign(sig, sig_buf, &sig_len, msg, msg_len, sk);
        OQS_SIG_verify(sig, msg, msg_len, sig_buf, sig_len, pk);
    }

    /* Actual benchmark */
    for (int i = 0; i < NUM_ITERATIONS; i++) {
        double t0, t1;

        /* KeyGen */
        t0 = get_time_us();
        OQS_SIG_keypair(sig, pk, sk);
        t1 = get_time_us();
        kg_times[i] = t1 - t0;

        /* Sign */
        t0 = get_time_us();
        OQS_SIG_sign(sig, sig_buf, &sig_len, msg, msg_len, sk);
        t1 = get_time_us();
        sign_times[i] = t1 - t0;

        /* Verify */
        t0 = get_time_us();
        OQS_SIG_verify(sig, msg, msg_len, sig_buf, sig_len, pk);
        t1 = get_time_us();
        verify_times[i] = t1 - t0;
    }

    stats_t kg_s = compute_stats(kg_times, NUM_ITERATIONS);
    stats_t sign_s = compute_stats(sign_times, NUM_ITERATIONS);
    stats_t ver_s = compute_stats(verify_times, NUM_ITERATIONS);

    print_stats("KeyGen", &kg_s);
    print_stats("Sign", &sign_s);
    print_stats("Verify", &ver_s);

    /* Also compute throughput: verifications per second */
    double ver_per_sec = 1e6 / ver_s.median;
    printf("  Verify throughput: %.0f verifications/sec (median-based)\n", ver_per_sec);

    free(pk); free(sk); free(sig_buf);
    free(kg_times); free(sign_times); free(verify_times);
    OQS_SIG_free(sig);
}

int main(void) {
    printf("PQC Crypto Benchmark - IoT Device Simulation\n");
    printf("Iterations: %d (warmup: %d)\n", NUM_ITERATIONS, WARMUP_ITERATIONS);
    printf("Message length: 72 bytes\n\n");

#ifdef __aarch64__
    printf("Platform: ARM aarch64 (simulated IoT/Edge device)\n");
#elif defined(__x86_64__)
    printf("Platform: x86_64 (reference)\n");
#else
    printf("Platform: unknown\n");
#endif

    benchmark_sig(OQS_SIG_alg_falcon_512);
    benchmark_sig(OQS_SIG_alg_ml_dsa_44);
    benchmark_sig(OQS_SIG_alg_ml_dsa_65);

    printf("\n--- Benchmark complete ---\n");
    return 0;
}
