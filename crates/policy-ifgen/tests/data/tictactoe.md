---
policy-version: 3
---

```policy
struct Players {
    X id,
    O id,
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
    let command = Move {
        gameID: gameID,
        X: x,
        Y: y,
    }
    publish command
}

effect GameUpdate {
    gameID id,
    player id,
    // the "dynamic" keyword is an annotation used to indicate to the consumer
    // that this value is not based on static event data and may change.
    p      string dynamic,
    X      int,
    Y      int,
}

effect GameOver {
    gameID id,
    winner id,
    p string,
}
```
