---
policy-version: 1
---

```policy
struct Players {
    X id,
    O id,
}

enum Player {
    X,
    O,
}

action StartGame(players struct Players) {
    publish Start {
        players: players,
    }
}

effect GameStart {
    gameID id,
    players struct Players,
}

action MakeMove(gameID id, x int, y int) {
    let move_command = Move {
        gameID: gameID,
        X: x,
        Y: y,
    }
    publish move_command
}

effect GameUpdate {
    gameID id,
    player id,
    // the "dynamic" keyword is an annotation used to indicate to the consumer
    // that this value is not based on static event data and may change.
    p      enum Player dynamic,
    X      int,
    Y      int,
}

effect GameOver {
    gameID id,
    winner id,
    p enum Player,
}
```
