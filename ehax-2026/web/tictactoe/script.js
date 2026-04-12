const cells = document.querySelectorAll(".cell");
const status = document.getElementById("status");
let board = Array(3)
  .fill()
  .map(() => Array(3).fill(0));
let active = true;

cells.forEach((cell) => {
  cell.addEventListener("click", async () => {
    const idx = parseInt(cell.dataset.index);
    const r = Math.floor(idx / 3);
    const col = idx % 3;

    if (board[r][col] !== 0 || !active) return;

    board[r][col] = 1;
    cell.innerText = "X";
    cell.style.color = "#00ff41";

    active = false;
    await syncWithCore();
  });
});

async function syncWithCore() {
  status.innerText = "AI ANALYSING...";
  try {
    const response = await fetch("/api", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode: "3x3", state: board }),
    });

    const data = await response.json();
    status.innerText = data.message;

    if (data.ai_move !== undefined && data.ai_move !== -1) {
      const r = Math.floor(data.ai_move / 3);
      const c = data.ai_move % 3;
      board[r][c] = -1;
      const aiCell = document.querySelector(`[data-index="${data.ai_move}"]`);
      aiCell.innerText = "O";
      aiCell.style.color = "#ff3333";
    }

    if (data.flag) {
      status.innerHTML = `<span style="color:#fff; text-shadow:0 0 10px #00ff41">${data.flag}</span>`;
      return;
    }

    if (data.gameOver || data.cheat) {
      active = false;
      setTimeout(resetGame, 3000);
    } else {
      active = true;
    }
  } catch (e) {
    status.innerText = "CONNECTION_LOST: Core offline.";
  }
}

function resetGame() {
  board = Array(3)
    .fill()
    .map(() => Array(3).fill(0));
  cells.forEach((c) => (c.innerText = ""));
  status.innerText = "Awaiting biometric handshake...";
  active = true;
}