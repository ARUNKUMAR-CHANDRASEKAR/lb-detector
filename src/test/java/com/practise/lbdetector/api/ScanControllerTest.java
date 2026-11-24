package com.practise.lbdetector.api;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * API contract tests. They never reach the network: the SSRF guard rejects loopback targets
 * before any probe is sent.
 */
@SpringBootTest
@AutoConfigureMockMvc
class ScanControllerTest {

    @Autowired
    MockMvc mvc;

    @Test
    void listsAllDetectors() throws Exception {
        mvc.perform(get("/api/v1/detectors"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(7))
                .andExpect(jsonPath("$[0].name").value("signature"));
    }

    @Test
    void rejectsLoopbackTargetWithProblemDetail() throws Exception {
        mvc.perform(post("/api/v1/scans").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"target\":\"http://127.0.0.1:8080/\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.title").value("Invalid target"));
    }

    @Test
    void rejectsNonHttpScheme() throws Exception {
        mvc.perform(post("/api/v1/scans").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"target\":\"ftp://example.com/\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void rejectsMissingTarget() throws Exception {
        mvc.perform(post("/api/v1/scans").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void healthEndpointIsUp() throws Exception {
        mvc.perform(get("/actuator/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
    }
}
