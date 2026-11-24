package com.practise.lbdetector.engine;

import com.practise.lbdetector.engine.model.Evidence;
import com.practise.lbdetector.engine.model.Evidence.Category;
import com.practise.lbdetector.engine.model.Verdict;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

class ScoringTest {

    private static Evidence e(String detector, double weight) {
        return Evidence.of(detector, weight, Category.BACKEND_POOL, "test", List.of());
    }

    @Test
    void noEvidenceMeansZero() {
        assertThat(ScanEngine.combine(List.of())).isZero();
    }

    @Test
    void independentDetectorsCombineWithNoisyOr() {
        // 1 - (1-0.5)(1-0.5) = 0.75
        assertThat(ScanEngine.combine(List.of(e("a", 0.5), e("b", 0.5)))).isCloseTo(0.75, within(1e-9));
    }

    @Test
    void oneDetectorRepeatingItselfIsCapped() {
        // four 0.25 signals from the same detector are capped at 0.25 + 0.1
        assertThat(ScanEngine.combine(List.of(e("latency", 0.25), e("latency", 0.25), e("latency", 0.25),
                e("latency", 0.25)))).isCloseTo(0.35, within(1e-9));
    }

    @Test
    void verdictThresholds() {
        assertThat(Verdict.fromConfidence(0.9)).isEqualTo(Verdict.LOAD_BALANCED);
        assertThat(Verdict.fromConfidence(0.6)).isEqualTo(Verdict.LIKELY_LOAD_BALANCED);
        assertThat(Verdict.fromConfidence(0.3)).isEqualTo(Verdict.POSSIBLY_LOAD_BALANCED);
        assertThat(Verdict.fromConfidence(0.1)).isEqualTo(Verdict.NO_EVIDENCE);
    }
}
