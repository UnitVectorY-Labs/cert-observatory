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

var TRUST_PATH_ICON_NAMESPACE = "http://www.w3.org/2000/svg";
var TRUST_PATH_TABLER_ICONS = {
    leaf: [
        "M12 3a9 9 0 1 0 9 9a9 9 0 0 0 -9 -9",
        "M3.6 9h16.8",
        "M3.6 15h16.8",
        "M11.5 3a17 17 0 0 0 0 18",
        "M12.5 3a17 17 0 0 1 0 18",
    ],
    intermediate: [
        "M12 15a3 3 0 1 0 6 0a3 3 0 1 0 -6 0",
        "M13 17.5v4.5l2 -1.5l2 1.5v-4.5",
        "M10 19h-5a2 2 0 0 1 -2 -2v-10c0 -1.1 .9 -2 2 -2h14a2 2 0 0 1 2 2v10a2 2 0 0 1 -1 1.73",
        "M6 9l12 0",
        "M6 12l3 0",
        "M6 15l2 0",
    ],
    root: [
        "M9 12l2 2l4 -4",
        "M12 3a9 9 0 1 0 9 9a9 9 0 0 0 -9 -9",
    ],
};

function getTrustPathNodeType(nodeEl) {
    if (!nodeEl || !nodeEl.classList) {
        return "";
    }
    if (nodeEl.classList.contains("leaf")) {
        return "leaf";
    }
    if (nodeEl.classList.contains("intermediate")) {
        return "intermediate";
    }
    if (nodeEl.classList.contains("root")) {
        return "root";
    }
    return "";
}

function getTrustPathNodeShape(nodeEl) {
    if (!nodeEl || !nodeEl.children) {
        return null;
    }
    for (var i = 0; i < nodeEl.children.length; i++) {
        var child = nodeEl.children[i];
        var tagName = (child.tagName || "").toLowerCase();
        if (tagName === "rect" || tagName === "polygon" || tagName === "path" || tagName === "circle" || tagName === "ellipse") {
            return child;
        }
    }
    return null;
}

function getTrustPathNodeLabel(nodeEl) {
    if (!nodeEl || !nodeEl.querySelector) {
        return null;
    }
    return nodeEl.querySelector("g.label, foreignObject, .nodeLabel, .label");
}

function expandTrustPathNodeShape(shapeEl, amount) {
    if (!shapeEl || shapeEl.dataset.tpExpanded === "true") {
        return;
    }
    if ((shapeEl.tagName || "").toLowerCase() !== "rect") {
        return;
    }

    var y = parseFloat(shapeEl.getAttribute("y") || "0");
    var height = parseFloat(shapeEl.getAttribute("height") || "0");
    if (!isFinite(y) || !isFinite(height)) {
        return;
    }

    shapeEl.setAttribute("y", String(y - amount));
    shapeEl.setAttribute("height", String(height + amount));
    shapeEl.dataset.tpExpanded = "true";
}

function getTrustPathNodeIconColor(nodeEl, nodeType) {
    var styles = window.getComputedStyle(document.documentElement);
    var cssVarName = "--mermaid-label";
    if (nodeEl && nodeEl.classList && nodeEl.classList.contains("missing")) {
        cssVarName = "--mermaid-missing-stroke";
    } else if (nodeType === "leaf") {
        cssVarName = "--mermaid-leaf-stroke";
    } else if (nodeType === "intermediate") {
        cssVarName = "--mermaid-intermediate-stroke";
    } else if (nodeType === "root") {
        cssVarName = "--mermaid-root-stroke";
    }

    var color = styles.getPropertyValue(cssVarName).trim();
    if (color) {
        return color;
    }

    if (cssVarName === "--mermaid-leaf-stroke") {
        return "#f97316";
    }
    if (cssVarName === "--mermaid-intermediate-stroke") {
        return "#38bdf8";
    }
    if (cssVarName === "--mermaid-root-stroke") {
        return "#22c55e";
    }
    if (cssVarName === "--mermaid-missing-stroke") {
        return "#ef4444";
    }
    return "#0f172a";
}

function buildTrustPathIcon(nodeType, iconSize, strokeColor) {
    var paths = TRUST_PATH_TABLER_ICONS[nodeType];
    if (!paths || !paths.length) {
        return null;
    }

    var iconGroup = document.createElementNS(TRUST_PATH_ICON_NAMESPACE, "g");
    iconGroup.setAttribute("class", "tp-node-icon");
    iconGroup.setAttribute("aria-hidden", "true");
    iconGroup.setAttribute("pointer-events", "none");
    iconGroup.setAttribute("data-base-stroke", strokeColor);
    iconGroup.setAttribute("style", "--tp-icon-stroke: " + strokeColor + ";");
    iconGroup.setAttribute("transform", "scale(" + (iconSize / 24).toFixed(4) + ")");

    for (var i = 0; i < paths.length; i++) {
        var path = document.createElementNS(TRUST_PATH_ICON_NAMESPACE, "path");
        path.setAttribute("d", paths[i]);
        path.setAttribute("fill", "none");
        path.setAttribute("stroke", strokeColor);
        path.setAttribute("stroke-width", "2");
        path.setAttribute("stroke-linecap", "round");
        path.setAttribute("stroke-linejoin", "round");
        path.setAttribute("vector-effect", "non-scaling-stroke");
        iconGroup.appendChild(path);
    }
    return iconGroup;
}

function decorateTrustPathMermaid(scope) {
    var root = scope || document;
    var svgs = root.querySelectorAll ? root.querySelectorAll(".trust-path-mermaid svg") : [];
    if (!svgs.length) {
        return;
    }

    for (var i = 0; i < svgs.length; i++) {
        var nodes = svgs[i].querySelectorAll(".node");
        for (var j = 0; j < nodes.length; j++) {
            var nodeEl = nodes[j];
            var nodeType = getTrustPathNodeType(nodeEl);
            if (!nodeType || nodeEl.querySelector(".tp-node-icon")) {
                continue;
            }

            var shapeEl = getTrustPathNodeShape(nodeEl);
            var labelEl = getTrustPathNodeLabel(nodeEl);
            if (!shapeEl || !labelEl || typeof shapeEl.getBBox !== "function" || typeof labelEl.getBBox !== "function") {
                continue;
            }

            expandTrustPathNodeShape(shapeEl, 18);

            var nodeBox = shapeEl.getBBox();
            var labelBox = labelEl.getBBox();
            var iconSize = Math.max(18, Math.min(22, nodeBox.height * 0.36));
            var iconX = nodeBox.x + ((nodeBox.width - iconSize) / 2);
            var iconY = nodeBox.y + 7;
            var labelShift = Math.max(0, (iconY + iconSize + 6) - labelBox.y);

            if (labelShift > 0) {
                var labelTransform = labelEl.getAttribute("transform") || "";
                labelEl.setAttribute("transform", (labelTransform + " translate(0 " + labelShift.toFixed(2) + ")").trim());
            }

            var iconGroup = buildTrustPathIcon(nodeType, iconSize, getTrustPathNodeIconColor(nodeEl, nodeType));
            if (!iconGroup) {
                continue;
            }
            iconGroup.setAttribute(
                "transform",
                "translate(" + iconX.toFixed(2) + " " + iconY.toFixed(2) + ") " + iconGroup.getAttribute("transform"),
            );

            nodeEl.insertBefore(iconGroup, labelEl);
        }
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
    mermaid.run({ nodes: Array.from(diagrams) }).then(function () {
        window.requestAnimationFrame(function () {
            decorateTrustPathMermaid(root);
        });
    }).catch(function (err) {
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

    var shapeEl = getTrustPathNodeShape(nodeEl);
    if (!shapeEl) {
        return;
    }

    if (isSelected) {
        shapeEl.style.setProperty("stroke-width", "5px", "important");
    } else {
        shapeEl.style.removeProperty("stroke-width");
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
