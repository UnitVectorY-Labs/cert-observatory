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
    mermaid.run({ nodes: Array.from(diagrams) }).then(function () {
        initializeTrustPathGraphControls(root);
    }).catch(function (err) {
        console.error("failed to render mermaid trust-path diagram", err);
    });
}

function parseSVGViewBox(svg) {
    var attr = svg.getAttribute("viewBox");
    if (!attr) {
        return null;
    }
    var parts = attr.trim().split(/[\s,]+/).map(Number);
    if (parts.length !== 4 || parts.some(function (part) { return !Number.isFinite(part); })) {
        return null;
    }
    return {
        x: parts[0],
        y: parts[1],
        width: parts[2],
        height: parts[3],
    };
}

function getSVGViewBox(svg) {
    var existing = parseSVGViewBox(svg);
    if (existing) {
        return existing;
    }

    var box = svg.getBBox ? svg.getBBox() : null;
    if (box && box.width > 0 && box.height > 0) {
        return {
            x: box.x,
            y: box.y,
            width: box.width,
            height: box.height,
        };
    }

    return { x: 0, y: 0, width: 800, height: 600 };
}

function setSVGViewBox(svg, viewBox) {
    svg.setAttribute("viewBox", [
        viewBox.x,
        viewBox.y,
        viewBox.width,
        viewBox.height,
    ].join(" "));
}

function fitViewBoxToSVGAspect(svg, viewBox) {
    var rect = svg.getBoundingClientRect();
    if (!rect.width || !rect.height || !viewBox.width || !viewBox.height) {
        return viewBox;
    }

    var svgRatio = rect.width / rect.height;
    var viewBoxRatio = viewBox.width / viewBox.height;
    if (!Number.isFinite(svgRatio) || !Number.isFinite(viewBoxRatio) || svgRatio <= 0 || viewBoxRatio <= 0) {
        return viewBox;
    }

    if (svgRatio > viewBoxRatio) {
        var expandedWidth = viewBox.height * svgRatio;
        return {
            x: viewBox.x - (expandedWidth - viewBox.width) / 2,
            y: viewBox.y,
            width: expandedWidth,
            height: viewBox.height,
        };
    }

    var expandedHeight = viewBox.width / svgRatio;
    return {
        x: viewBox.x,
        y: viewBox.y - (expandedHeight - viewBox.height) / 2,
        width: viewBox.width,
        height: expandedHeight,
    };
}

function getTrustPathGraphState(svg) {
    if (!svg.__trustPathPanZoom) {
        var initial = fitViewBoxToSVGAspect(svg, getSVGViewBox(svg));
        svg.__trustPathPanZoom = {
            initial: Object.assign({}, initial),
            current: Object.assign({}, initial),
        };
        setSVGViewBox(svg, initial);
    }
    return svg.__trustPathPanZoom;
}

function clampTrustPathViewBox(svg, next) {
    var state = getTrustPathGraphState(svg);
    var minWidth = state.initial.width / 8;
    var maxWidth = state.initial.width * 2.5;
    var width = Math.max(minWidth, Math.min(maxWidth, next.width));
    var height = width * (state.initial.height / state.initial.width);
    return {
        x: next.x,
        y: next.y,
        width: width,
        height: height,
    };
}

function zoomTrustPathGraph(svg, factor, clientX, clientY) {
    var state = getTrustPathGraphState(svg);
    var rect = svg.getBoundingClientRect();
    var focusX = typeof clientX === "number" && rect.width > 0 ? (clientX - rect.left) / rect.width : 0.5;
    var focusY = typeof clientY === "number" && rect.height > 0 ? (clientY - rect.top) / rect.height : 0.5;
    var nextWidth = state.current.width * factor;
    var nextHeight = state.current.height * factor;
    var next = clampTrustPathViewBox(svg, {
        x: state.current.x + (state.current.width - nextWidth) * focusX,
        y: state.current.y + (state.current.height - nextHeight) * focusY,
        width: nextWidth,
        height: nextHeight,
    });

    state.current = next;
    setSVGViewBox(svg, next);
}

function resetTrustPathGraph(svg) {
    var state = getTrustPathGraphState(svg);
    state.current = Object.assign({}, state.initial);
    setSVGViewBox(svg, state.current);
}

function findTrustPathSVG(control) {
    var section = control && control.closest ? control.closest(".section-card") : null;
    return section ? section.querySelector(".trust-path-mermaid svg") : null;
}

function initializeTrustPathPanZoom(svg) {
    if (!svg || svg.dataset.trustPathPanZoom === "ready") {
        return;
    }
    svg.dataset.trustPathPanZoom = "ready";
    svg.setAttribute("role", "img");
    svg.style.touchAction = "none";
    getTrustPathGraphState(svg);

    var drag = {
        active: false,
        moved: false,
        pointerId: null,
        clientX: 0,
        clientY: 0,
    };

    svg.addEventListener("pointerdown", function (evt) {
        if (evt.button !== 0) {
            return;
        }
        if (evt.target && evt.target.closest && evt.target.closest(".node")) {
            drag.active = false;
            drag.moved = false;
            return;
        }
        drag.active = true;
        drag.moved = false;
        drag.pointerId = evt.pointerId;
        drag.clientX = evt.clientX;
        drag.clientY = evt.clientY;
        evt.currentTarget.classList.add("is-panning");
        evt.currentTarget.setPointerCapture(evt.pointerId);
    });

    svg.addEventListener("pointermove", function (evt) {
        if (!drag.active || drag.pointerId !== evt.pointerId) {
            return;
        }
        var svgEl = evt.currentTarget;
        var state = getTrustPathGraphState(svgEl);
        var rect = svgEl.getBoundingClientRect();
        if (rect.width <= 0 || rect.height <= 0) {
            return;
        }
        var dx = evt.clientX - drag.clientX;
        var dy = evt.clientY - drag.clientY;
        if (Math.abs(dx) + Math.abs(dy) > 3) {
            drag.moved = true;
        }
        drag.clientX = evt.clientX;
        drag.clientY = evt.clientY;
        state.current = {
            x: state.current.x - dx * (state.current.width / rect.width),
            y: state.current.y - dy * (state.current.height / rect.height),
            width: state.current.width,
            height: state.current.height,
        };
        setSVGViewBox(svgEl, state.current);
    });

    svg.addEventListener("pointerup", function (evt) {
        if (drag.active && drag.pointerId === evt.pointerId) {
            evt.currentTarget.classList.remove("is-panning");
            drag.active = false;
        }
    });

    svg.addEventListener("pointercancel", function (evt) {
        evt.currentTarget.classList.remove("is-panning");
        drag.active = false;
    });

    svg.addEventListener("click", function (evt) {
        var nodeEl = evt.target && evt.target.closest ? evt.target.closest(".node.interactive") : null;
        if (nodeEl) {
            evt.preventDefault();
            evt.stopImmediatePropagation();
            drag.moved = false;
            selectTrustPathCertFromMermaid(getRenderedMermaidNodeID(nodeEl));
            return;
        }
        if (drag.moved) {
            evt.preventDefault();
            evt.stopImmediatePropagation();
            drag.moved = false;
        }
    }, true);
}

function initializeTrustPathGraphControls(scope) {
    var root = scope || document;
    var wrappers = root.querySelectorAll ? root.querySelectorAll(".trust-path-mermaid") : [];
    for (var i = 0; i < wrappers.length; i++) {
        initializeTrustPathPanZoom(wrappers[i].querySelector("svg"));
    }

    var controls = root.querySelectorAll ? root.querySelectorAll("[data-graph-action]") : [];
    for (var j = 0; j < controls.length; j++) {
        if (controls[j].dataset.graphControls === "ready") {
            continue;
        }
        controls[j].dataset.graphControls = "ready";
        controls[j].addEventListener("click", function (evt) {
            var svg = findTrustPathSVG(evt.currentTarget);
            if (!svg) {
                return;
            }
            if (evt.currentTarget.dataset.graphAction === "zoom-in") {
                zoomTrustPathGraph(svg, 0.8);
            } else if (evt.currentTarget.dataset.graphAction === "zoom-out") {
                zoomTrustPathGraph(svg, 1.25);
            } else {
                resetTrustPathGraph(svg);
            }
        });
    }
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

function switchCertDecodeTab(button, selected) {
    var root = button && button.closest ? button.closest("[data-cert-tabs]") : null;
    if (!root) {
        return;
    }

    var buttons = root.querySelectorAll("[data-cert-tab-button]");
    for (var i = 0; i < buttons.length; i++) {
        var isActive = buttons[i].dataset.certTabButton === selected;
        buttons[i].classList.toggle("is-active", isActive);
        buttons[i].setAttribute("aria-selected", String(isActive));
    }

    var panels = root.querySelectorAll("[data-cert-tab-panel]");
    for (var j = 0; j < panels.length; j++) {
        var isSelected = panels[j].dataset.certTabPanel === selected;
        panels[j].classList.toggle("hidden", !isSelected);
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

function getRenderedMermaidNodeID(nodeEl) {
    if (!nodeEl) {
        return "";
    }
    if (nodeEl.dataset && nodeEl.dataset.id) {
        return nodeEl.dataset.id;
    }

    var mapEntries = document.querySelectorAll(".tp-node-map");
    var renderedID = nodeEl.id || "";
    for (var i = 0; i < mapEntries.length; i++) {
        var nodeID = mapEntries[i].dataset.nodeId;
        if (renderedID === nodeID || renderedID.indexOf("-" + nodeID + "-") !== -1) {
            return nodeID;
        }
    }
    return renderedID;
}

function findRenderedMermaidEdges(nodeId) {
    if (!nodeId) {
        return [];
    }
    // In Mermaid v11, edges are <path class="flowchart-link"> with IDs like L_n0_n1_0.
    var allEdgePaths = document.querySelectorAll(".trust-path-mermaid path.flowchart-link");
    var matches = [];
    var escapedId = nodeId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    var pattern = new RegExp("^L_" + escapedId + "_|_" + escapedId + "_");
    for (var i = 0; i < allEdgePaths.length; i++) {
        var el = allEdgePaths[i];
        var id = el.id || "";
        if (pattern.test(id)) {
            matches.push(el);
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

    var allEdges = document.querySelectorAll(".trust-path-mermaid path.flowchart-link");
    for (var e = 0; e < allEdges.length; e++) {
        allEdges[e].classList.remove("tp-active-edge");
    }

    var activeNodes = findRenderedMermaidNodes(nodeId);
    for (var k = 0; k < activeNodes.length; k++) {
        activeNodes[k].classList.add("tp-active");
        setTrustPathNodeSelected(activeNodes[k], true);
    }

    var activeEdges = findRenderedMermaidEdges(nodeId);
    for (var j = 0; j < activeEdges.length; j++) {
        activeEdges[j].classList.add("tp-active-edge");
    }

    var chainHeading = document.getElementById("chain-heading");
    if (chainHeading) {
        chainHeading.style.display = "none";
    }

    var selectedHeading = document.getElementById("selected-cert-heading");
    if (selectedHeading) {
        selectedHeading.style.display = "block";
    }

    var chainList = document.getElementById("certificate-chain-list");
    if (chainList) {
        chainList.style.display = "none";
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
