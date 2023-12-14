---
policy-version: 3
---

```policy
action StartGame(profileX id, profileO id) {
    let command = Start{
        ProfileX: profileX,
        ProfileO: profileO,
    }
    emit command
}

effect GameStart {
    gameID id,
    x id,
    o id,
}

action MakeMove(gameID id, x int, y int) {
    let command = Move {
        gameID: gameID,
        X: x,
        Y: y,
    }
    emit command
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
