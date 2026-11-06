---
policy-version: 2
---

```policy
struct Players {
    X: id,
    O: id,
}

enum Player {
    X,
    O,
}

base[basic] Base {
    get_key(_dev: id) option[bytes] { return None }
}

command Start with Base {
    fields {
        players: struct Players
    }
    policy {
        finish {}
    }
}

command Move with Base {
    fields {
        gameID: id,
        X: int,
        Y: int,
    }
    policy {
        finish {}
    }
}


action[basic] StartGame(players: struct Players) {
    publish Start { players }
}

effect GameStart {
    gameID: id,
    players: struct Players,
}

action[basic] MakeMove(gameID: id, x: int, y: int) {
    let move_command = Move {
        gameID,
        X: x,
        Y: y,
    }
    publish move_command
}

effect GameUpdate {
    gameID: id,
    player: id,
    p:      enum Player,
    X:      int,
    Y:      int,
}

effect GameOver {
    gameID: id,
    winner: id,
    p: enum Player,
}

action[ephemeral] Temporary(n: int, s: string) {}
```
