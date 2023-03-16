---
policy-version: 3
---

```policy
fact Players[gameID ID]=>{x ID, o ID}
fact NextPlayer[gameID ID]=>{p string}
fact Field[gameID ID, x int, y int]=>{p string}
fact GameOver[gameID ID]=>{}

// Regular functions can only contain data processing statements, must
// have a return type, and must return a value
function bounds(v int) bool {
    return v >= 0 && v <= 2
}
// finish functions can only be used in finish blocks and can only contain
// statements valid in finish blocks
finish function set_next_player(gameID ID, to string) {
    update NextPlayer[gameID: gameID] to {p: to}
}

action StartGame(profileX ID, profileO ID) {
    let command = Start{
        ProfileX: profileX,
        ProfileO: profileO,
    }
    emit command
}

effect GameStart {
    gameID ID,
    x ID,
    o ID,
}

command Start {
    fields {
        ProfileX ID,
        ProfileO ID,
    }

    policy {
        check ProfileX != ProfileO
        // id() is a function that calculates the ID of this command from its
        // content.
        let gameID = id(self)

        finish {
            create PlayerProfile[gameID: gameID]=>{x: ProfileX, o: ProfileO}
            create NextPlayer[gameID: gameID]=>{p: "X"}

            effect GameStart{
                gameID: gameID,
                x: ProfileX,
                o: ProfileO,
            }
        }
    }
}

action MakeMove(gameID ID, x int, y int) {
    let command = Move {
        gameID: gameID,
        X: x,
        Y: y,
    }
    emit command
}

effect GameUpdate {
    gameID ID,
    player ID,
    // the "dynamic" keyword is an annotation used to indicate to the consumer
    // that this value is not based on static event data and may change.
    p      string dynamic,
    X      int,
    Y      int,
}

effect GameOver {
    gameID ID,
    winner ID,
    p string,
}

command Move {
    // phase 0: command field definition
    fields {
        gameID ID,
        X int,
        Y int,
    }

    policy {
        // phase 1: variable definition/checks
        // These aren't "variables" in the procedural sense, they are
        // set-once constant definitions that can be used in later
        // expressions.
        // `author` is a built-in function which returns an ID for the author
        // of a command.
        let player = author_id(self)
        // the query expression searches the fact database for facts which
        // match the signature, returning an Optional containing either all
        // values marked with ?, or None. The unwrap expression returns the
        // value inside an Optional or terminates rule execution.
        let result = unwrap query PlayerProfile[gameID: gameID]=>{x: ?, o: ?}
        let playerX = result.x
        let playerO = result.o
        let p = unwrap query NextPlayer[gameID: gameID]=>{p: ?}
        // the if expression works like a ternary expression, where both
        // branches must be specified.
        let nextp = if p == "X" then "O" else "X"

        // Checks are separated here, but they can be interleaved with let
        // statements.
        // Defined variables, command fields, and common event fields can
        // be checked for validity with boolean expressions.
        check (p == "X" && player == playerX) || (p == "O" && player == playerO)
        // functions can be used in any expression
        check bounds(X)
        check bounds(Y)

        // phase 2: fact updates and effects
        // Facts can be created, updated, and destroyed.
        // Zero or more effects can be generated.
        // The finish block ends rule evaluation.
        finish {
            create Field[gameID: gameID, x: X, y: Y]=>{p: p}
            set_next_player(gameID, nextp)

            effect GameUpdate{
                gameID: gameID,
                player: player,
                p: p,
                X: X,
                Y: Y,
            }
        }
    }
}

function game_over(gameID ID, x int, y int, p string) bool {
    let f00 = if x == 0 && y == 0 then Some p else query Field[gameID: gameID, x: 0, y: 0]=>{p: ?}
    let f10 = if x == 1 && y == 0 then Some p else query Field[gameID: gameID, x: 1, y: 0]=>{p: ?}
    let f20 = if x == 2 && y == 0 then Some p else query Field[gameID: gameID, x: 2, y: 0]=>{p: ?}
    let f01 = if x == 0 && y == 1 then Some p else query Field[gameID: gameID, x: 0, y: 1]=>{p: ?}
    let f11 = if x == 1 && y == 1 then Some p else query Field[gameID: gameID, x: 1, y: 1]=>{p: ?}
    let f21 = if x == 2 && y == 1 then Some p else query Field[gameID: gameID, x: 2, y: 1]=>{p: ?}
    let f02 = if x == 0 && y == 2 then Some p else query Field[gameID: gameID, x: 0, y: 2]=>{p: ?}
    let f12 = if x == 1 && y == 2 then Some p else query Field[gameID: gameID, x: 1, y: 2]=>{p: ?}
    let f22 = if x == 2 && y == 2 then Some p else query Field[gameID: gameID, x: 2, y: 2]=>{p: ?}
    return (f00 is Some && f00 == f10 && f10 == f20) ||
           (f01 is Some && f01 == f11 && f11 == f21) ||
           (f01 is Some && f02 == f12 && f12 == f22) ||
           (f00 is Some && f00 == f01 && f01 == f02) ||
           (f10 is Some && f10 == f11 && f11 == f12) ||
           (f20 is Some && f20 == f21 && f21 == f22) ||
           (f00 is Some && f00 == f11 && f11 == f22) ||
           (f20 is Some && f20 == f11 && f11 == f02)
}

command Move2 {
    fields {
        gameID ID,
        X int,
        Y int,
    }

    policy {
        let player = author(self)
        let players = unwrap query PlayerProfile[gameID: gameID]=>{x: ?, o: ?}
        let p = unwrap query NextPlayer[gameID: gameID]=>{p: ?}
        let nextp = if p == "X" then "O" else "X"

        check !exists GameOver[gameID: gameID]=>{}
        check bounds(X)
        check bounds(Y)
        check (p == "X" && player == players.x) || (p == "O" && player == players.o)

        match game_over(gameID, X, Y, p) {
            true => {
                finish {
                    create Field[gameID: gameID, x: X, y: Y]=>{p: p}
                    delete NextPlayer[gameID: gameID]=>{p: p}
                    create GameOver[gameID: gameID]=>{}
                    effect GameOver{
                        gameID: gameID,
                        winner: player,
                        p: p,
                    }
                }
            }
            false => {
                finish {
                    create Field[gameID: gameID, x: X, y: Y]=>{p: p}
                    set_next_player(gameID, op)
                    effect GameUpdate{
                        gameID: gameID,
                        player: player,
                        p: p,
                        x: X,
                        y: Y,
                    }
                }
            }
        }
    }
}
```