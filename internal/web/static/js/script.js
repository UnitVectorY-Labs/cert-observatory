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

function hexToCompact(str) {
    return str.replace(/:/g, "").toUpperCase();
}

function hexToColon(str) {
    var clean = str.replace(/:/g, "").toLowerCase();
    var pairs = [];
    for (var i = 0; i < clean.length; i += 2) {
        pairs.push(clean.substring(i, i + 2));
    }
    return pairs.join(":");
}

function getHexFormat() {
    try {
        return localStorage.getItem("hexFormat") || "colon";
    } catch (err) {
        return "colon";
    }
}

function setHexFormat(fmt) {
    try {
        localStorage.setItem("hexFormat", fmt);
    } catch (err) {
        // Ignore storage failures.
    }
}

function applyHexFormat(scope) {
    var root = scope || document;
    var fmt = getHexFormat();
    var elements = root.querySelectorAll ? root.querySelectorAll(".hex-value") : [];
    for (var i = 0; i < elements.length; i++) {
        var el = elements[i];
        if (!el.dataset.hexColon) {
            el.dataset.hexColon = el.textContent.trim();
        }
        if (fmt === "compact") {
            el.textContent = hexToCompact(el.dataset.hexColon);
        } else {
            el.textContent = el.dataset.hexColon;
        }
    }
    updateHexToggleLabel(fmt);
}

function updateHexToggleLabel(fmt) {
    var label = document.getElementById("hex-toggle-label");
    if (label) {
        label.textContent = fmt === "compact" ? "AABB" : "aa:bb";
    }
    var btn = document.getElementById("hex-toggle");
    if (btn) {
        btn.setAttribute("aria-label", fmt === "compact" ? "Switch to colon hex format" : "Switch to compact hex format");
    }
}

function toggleHexFormat() {
    var current = getHexFormat();
    var next = current === "compact" ? "colon" : "compact";
    setHexFormat(next);
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

    var hexBtn = document.getElementById("hex-toggle");
    if (hexBtn) {
        hexBtn.addEventListener("click", toggleHexFormat);
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
