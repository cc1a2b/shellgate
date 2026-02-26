// ShellGate Terminal Client
(function () {
    "use strict";

    const RECONNECT_BASE = 1000;
    const RECONNECT_MAX = 30000;
    const RECONNECT_MULTIPLIER = 2;

    let term;
    let ws;
    let reconnectDelay = RECONNECT_BASE;
    let reconnectTimer = null;
    let fitAddon;

    const statusOverlay = document.getElementById("status-overlay");
    const statusText = document.getElementById("status-text");
    const statusDetail = document.getElementById("status-detail");

    function showStatus(text, detail) {
        statusText.textContent = text;
        statusDetail.textContent = detail || "";
        statusOverlay.classList.add("visible");
    }

    function hideStatus() {
        statusOverlay.classList.remove("visible");
    }

    function initTerminal() {
        term = new Terminal({
            fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
            fontSize: 14,
            cursorBlink: true,
            cursorStyle: "block",
            allowProposedApi: true,
            scrollback: 10000,
            theme: {
                background: "#1a1b26",
                foreground: "#a9b1d6",
                cursor: "#c0caf5",
                selectionBackground: "#33467c",
                black: "#15161e",
                red: "#f7768e",
                green: "#9ece6a",
                yellow: "#e0af68",
                blue: "#7aa2f7",
                magenta: "#bb9af7",
                cyan: "#7dcfff",
                white: "#a9b1d6",
                brightBlack: "#414868",
                brightRed: "#f7768e",
                brightGreen: "#9ece6a",
                brightYellow: "#e0af68",
                brightBlue: "#7aa2f7",
                brightMagenta: "#bb9af7",
                brightCyan: "#7dcfff",
                brightWhite: "#c0caf5",
            },
        });

        fitAddon = new FitAddon.FitAddon();
        term.loadAddon(fitAddon);
        term.loadAddon(new WebLinksAddon.WebLinksAddon());

        term.open(document.getElementById("terminal"));
        fitAddon.fit();

        term.onData(function (data) {
            sendMessage({ type: "input", data: data });
        });

        term.onResize(function (size) {
            sendMessage({ type: "resize", cols: size.cols, rows: size.rows });
        });

        window.addEventListener("resize", function () {
            fitAddon.fit();
        });

        connect();
    }

    function getWebSocketURL() {
        const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
        return proto + "//" + window.location.host + "/ws";
    }

    function sendMessage(msg) {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify(msg));
        }
    }

    function connect() {
        if (ws) {
            ws.close();
            ws = null;
        }

        showStatus("Connecting...", "");

        const url = getWebSocketURL();
        ws = new WebSocket(url);

        ws.onopen = function () {
            hideStatus();
            reconnectDelay = RECONNECT_BASE;

            // Send initial terminal size
            sendMessage({
                type: "resize",
                cols: term.cols,
                rows: term.rows,
            });

            term.focus();
        };

        ws.onmessage = function (event) {
            try {
                const msg = JSON.parse(event.data);
                switch (msg.type) {
                    case "output":
                        term.write(msg.data);
                        break;
                    case "pong":
                        // keepalive response
                        break;
                    default:
                        break;
                }
            } catch (e) {
                console.error("Failed to parse message:", e);
            }
        };

        ws.onclose = function (event) {
            if (event.code === 1000) {
                showStatus("Session ended", "The shell process has exited.");
                return;
            }
            scheduleReconnect();
        };

        ws.onerror = function () {
            // onclose will fire after onerror
        };
    }

    function scheduleReconnect() {
        if (reconnectTimer) return;

        const delay = reconnectDelay;
        reconnectDelay = Math.min(reconnectDelay * RECONNECT_MULTIPLIER, RECONNECT_MAX);

        showStatus("Disconnected", "Reconnecting in " + Math.round(delay / 1000) + "s...");

        reconnectTimer = setTimeout(function () {
            reconnectTimer = null;
            connect();
        }, delay);
    }

    // Initialize when DOM is ready
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initTerminal);
    } else {
        initTerminal();
    }
})();
