(function () {
    try {
        var saved = localStorage.getItem("theme");
        if (saved === "light") {
            document.documentElement.classList.remove("dark");
        } else {
            document.documentElement.classList.add("dark");
        }
    } catch (err) {
        document.documentElement.classList.add("dark");
    }
})();

window.htmx = window.htmx || {};
window.htmx.config = window.htmx.config || {};
window.htmx.config.allowEval = false;

function updateThemeToggleLabel(isDark) {
    var btn = document.getElementById("theme-toggle");
    if (!btn) {
        return;
    }
    var labelEl = btn.querySelector("[data-theme-label]");
    if (labelEl) {
        labelEl.textContent = isDark ? "Light mode" : "Dark mode";
    }
    btn.setAttribute("aria-pressed", String(isDark));
    btn.setAttribute("aria-label", isDark ? "Switch to light mode" : "Switch to dark mode");
}

function setTheme(theme) {
    var dark = theme !== "light";
    document.documentElement.classList.toggle("dark", dark);
    updateThemeToggleLabel(dark);
    try {
        localStorage.setItem("theme", dark ? "dark" : "light");
    } catch (err) {
        // Ignore storage failures.
    }
}

function toggleTheme() {
    var currentlyDark = document.documentElement.classList.contains("dark");
    setTheme(currentlyDark ? "light" : "dark");
}

function clearResults() {
    var results = document.getElementById("results");
    if (results) {
        results.innerHTML = "";
    }
}

function renderTrustPathMermaid(scope) {
    if (!window.mermaid) {
        return;
    }
    var root = scope || document;
    var diagrams = root.querySelectorAll ? root.querySelectorAll(".trust-path-mermaid .mermaid") : [];
    if (!diagrams.length) {
        return;
    }
    mermaid.run({ nodes: Array.from(diagrams) }).catch(function (err) {
        console.error("failed to render mermaid trust-path diagram", err);
    });
}

function copyPEM(button, certHash) {
    var pemBlock = document.getElementById("pem-" + certHash);
    if (pemBlock) {
        navigator.clipboard.writeText(pemBlock.textContent).then(function () {
            var originalHTML = button.innerHTML;
            button.textContent = "Copied!";
            button.classList.add("copied");
            setTimeout(function () {
                button.innerHTML = originalHTML;
                button.classList.remove("copied");
            }, 1500);
        });
    }
}

// Mermaid click callback: maps Mermaid node IDs to certificate indices.
function selectTrustPathCertFromMermaid(nodeId) {
    var mapEntries = document.querySelectorAll(".tp-node-map");
    var certIdx = -1;
    for (var i = 0; i < mapEntries.length; i++) {
        if (mapEntries[i].dataset.nodeId === nodeId) {
            certIdx = parseInt(mapEntries[i].dataset.certIdx, 10);
            break;
        }
    }

    selectTrustPathCert(nodeId, certIdx);
}

function findRenderedMermaidNodes(nodeId) {
    if (!nodeId) {
        return [];
    }

    var normalizedNodeId = String(nodeId);
    var escapedNodeId = normalizedNodeId.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
    var byDataID = document.querySelectorAll('.trust-path-mermaid .node[data-id="' + escapedNodeId + '"]');
    if (byDataID.length > 0) {
        return Array.from(byDataID);
    }

    var direct = document.getElementById(normalizedNodeId);
    if (direct && direct.classList && direct.classList.contains("node")) {
        return [direct];
    }

    var allNodes = document.querySelectorAll(".trust-path-mermaid .node");
    var matches = [];
    for (var i = 0; i < allNodes.length; i++) {
        var candidateID = allNodes[i].id || "";
        if (candidateID === normalizedNodeId || candidateID.indexOf("-" + normalizedNodeId + "-") !== -1) {
            matches.push(allNodes[i]);
        }
    }
    return matches;
}

function setTrustPathNodeSelected(nodeEl, isSelected) {
    if (!nodeEl) {
        return;
    }

    var shapes = nodeEl.querySelectorAll("rect, polygon, path, circle, ellipse");
    for (var i = 0; i < shapes.length; i++) {
        if (isSelected) {
            shapes[i].style.setProperty("stroke-width", "5px", "important");
        } else {
            shapes[i].style.removeProperty("stroke-width");
        }
    }
}

// Trust path graph: reveal the pre-rendered detail pane for the clicked node.
function selectTrustPathCert(nodeId, certIdx) {
    if (certIdx < 0) {
        return;
    }

    var allNodes = document.querySelectorAll(".trust-path-mermaid .node");
    for (var i = 0; i < allNodes.length; i++) {
        allNodes[i].classList.remove("tp-active");
        setTrustPathNodeSelected(allNodes[i], false);
    }

    var activeNodes = findRenderedMermaidNodes(nodeId);
    for (var k = 0; k < activeNodes.length; k++) {
        activeNodes[k].classList.add("tp-active");
        setTrustPathNodeSelected(activeNodes[k], true);
    }

    var chainSection = document.getElementById("chain-view-section");
    if (chainSection) {
        chainSection.style.display = "none";
    }

    var selectedHeading = document.getElementById("selected-cert-heading");
    if (selectedHeading) {
        selectedHeading.style.display = "block";
    }

    var allPanes = document.querySelectorAll(".trust-path-cert-pane");
    for (var j = 0; j < allPanes.length; j++) {
        allPanes[j].style.display = "none";
    }

    var targetPane = document.getElementById("trust-cert-pane-" + certIdx);
    if (targetPane) {
        targetPane.style.display = "block";
        targetPane.scrollIntoView({ behavior: "smooth", block: "start" });
    }
}

function downloadTrustPathCerts(button) {
    var domain = (button && button.dataset && button.dataset.domain) ? button.dataset.domain : "certificates";
    var panes = document.querySelectorAll(".trust-path-cert-pane");
    var parts = [];

    for (var i = 0; i < panes.length; i++) {
        var pemBlock = panes[i].querySelector(".trust-path-pem");
        if (!pemBlock) { continue; }

        var subject = pemBlock.dataset.subject || "";
        var issuer = pemBlock.dataset.issuer || "";
        var serial = pemBlock.dataset.serial || "";
        var notBefore = pemBlock.dataset.notBefore || "";
        var notAfter = pemBlock.dataset.notAfter || "";
        var pem = pemBlock.textContent.trim();

        if (!pem) { continue; }

        var header = [];
        if (subject)   { header.push("# Subject: " + subject); }
        if (issuer)    { header.push("# Issuer: " + issuer); }
        if (serial)    { header.push("# Serial: " + serial); }
        if (notBefore) { header.push("# Not Before: " + notBefore); }
        if (notAfter)  { header.push("# Not After: " + notAfter); }

        parts.push(header.join("\n") + "\n" + pem);
    }

    if (parts.length === 0) { return; }

    var content = parts.join("\n\n") + "\n";
    var filename = domain.replace(/[^a-zA-Z0-9.-]/g, "_") + "-certificates.pem";

    var blob = new Blob([content], { type: "application/x-pem-file" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function getHexSeparator() {
    try {
        return localStorage.getItem("hexSeparator") || "colon";
    } catch (err) {
        return "colon";
    }
}

function setHexSeparator(value) {
    try {
        localStorage.setItem("hexSeparator", value);
    } catch (err) {
        // Ignore storage failures.
    }
}

function getHexCase() {
    try {
        return localStorage.getItem("hexCase") || "lower";
    } catch (err) {
        return "lower";
    }
}

function setHexCase(value) {
    try {
        localStorage.setItem("hexCase", value);
    } catch (err) {
        // Ignore storage failures.
    }
}

function formatHexValue(colonStr, separator, hexCase) {
    var clean = colonStr.replace(/:/g, "").toLowerCase();
    var result;
    if (separator === "colon") {
        var pairs = [];
        for (var i = 0; i < clean.length; i += 2) {
            pairs.push(clean.substring(i, i + 2));
        }
        result = pairs.join(":");
    } else {
        result = clean;
    }
    if (hexCase === "upper") {
        result = result.toUpperCase();
    }
    return result;
}

function applyHexFormat(scope) {
    var root = scope || document;
    var separator = getHexSeparator();
    var hexCase = getHexCase();
    var elements = root.querySelectorAll ? root.querySelectorAll(".hex-value") : [];
    for (var i = 0; i < elements.length; i++) {
        var el = elements[i];
        if (!el.dataset.hexColon) {
            el.dataset.hexColon = el.textContent.trim();
        }
        el.textContent = formatHexValue(el.dataset.hexColon, separator, hexCase);
    }
    updateHexSeparatorLabel(separator);
    updateHexCaseLabel(hexCase);
}

function updateHexSeparatorLabel(separator) {
    var label = document.getElementById("hex-separator-label");
    if (label) {
        label.textContent = separator === "colon" ? "aa:bb" : "aabb";
    }
    var btn = document.getElementById("hex-separator-toggle");
    if (btn) {
        btn.setAttribute("aria-label", separator === "colon" ? "Switch to compact hex format" : "Switch to colon-separated hex format");
    }
}

function updateHexCaseLabel(hexCase) {
    var label = document.getElementById("hex-case-label");
    if (label) {
        label.textContent = hexCase === "lower" ? "aa" : "AA";
    }
    var btn = document.getElementById("hex-case-toggle");
    if (btn) {
        btn.setAttribute("aria-label", hexCase === "lower" ? "Switch to uppercase hex" : "Switch to lowercase hex");
    }
}

function toggleHexSeparator() {
    var current = getHexSeparator();
    var next = current === "colon" ? "none" : "colon";
    setHexSeparator(next);
    applyHexFormat(document);
}

function toggleHexCase() {
    var current = getHexCase();
    var next = current === "lower" ? "upper" : "lower";
    setHexCase(next);
    applyHexFormat(document);
}

function initializePage() {
    if (window.mermaid) {
        mermaid.initialize({
            startOnLoad: false,
            securityLevel: "loose",
        });
    }

    var toggle = document.getElementById("theme-toggle");
    if (toggle) {
        toggle.addEventListener("click", toggleTheme);
        updateThemeToggleLabel(document.documentElement.classList.contains("dark"));
    }

    var hexSepBtn = document.getElementById("hex-separator-toggle");
    if (hexSepBtn) {
        hexSepBtn.addEventListener("click", toggleHexSeparator);
    }
    var hexCaseBtn = document.getElementById("hex-case-toggle");
    if (hexCaseBtn) {
        hexCaseBtn.addEventListener("click", toggleHexCase);
    }
    applyHexFormat(document);

    document.addEventListener("htmx:beforeRequest", function (evt) {
        if (evt.target && evt.target.id === "inspect-form") {
            clearResults();
        }
    });

    if (document.body) {
        document.body.addEventListener("htmx:beforeSwap", function (evt) {
            if (evt.detail.xhr.status >= 400 && evt.detail.xhr.status < 600) {
                evt.detail.shouldSwap = true;
                evt.detail.isError = false;
            }
        });

        document.body.addEventListener("htmx:afterSwap", function (evt) {
            renderTrustPathMermaid(evt.target);
            applyHexFormat(evt.target);
        });
    }

    renderTrustPathMermaid(document);
}

if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initializePage);
} else {
    initializePage();
}
