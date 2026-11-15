package main

import "core:fmt"
import "core:slice"
import "core:math/rand"

import "core:math/big"

// import "core:crypto/rsa"
import "./rsa"
import "core:crypto/hash"

ROUND_COUNT :: 3

Country :: enum {
    Ukraine,
    Russia,
    Poland,
}

Person :: struct {
    id : u64,
    fullname : string,
    country : Country,
    age : int,

    rememberedSalts : [dynamic]u64,
    rememberedViolation : bool,

    key_prv : rsa.Key_Private,
    key_pub : rsa.Key_Public,
}

Candidate :: struct {
    id : u64,
    id_multipliers : [8]u8,

    fullname : string,

    votes : int,
}




Voter :: struct {
    key_pub : rsa.Key_Public,
}







Ballot :: struct {
    candidate_id : u64,
}



main :: proc () {
    people : []Person = {
        Person{ id = 0, fullname = "Vitalya Gryb", country = .Ukraine, age = 23 },
        Person{ id = 1, fullname = "Svitlana Zhizha", country = .Ukraine, age = 27 },
        Person{ id = 2, fullname = "Zheka Zrada", country = .Ukraine, age = 19 },
        Person{ id = 3, fullname = "Grzegorz Brzeczyszczykiewicz", country = .Ukraine, age = 153 },
        Person{ id = 5, fullname = "Yaroslav Aboba", country = .Ukraine, age = 34 },
    }



    for &p in people {
        p.key_prv, p.key_pub = rsa.keygen()
        fmt.printfln("Generated private key for %v", p.fullname)
    }
    fmt.println()



    voters : [dynamic]Voter
    for &p in people {
        append(&voters, Voter{
            key_pub = p.key_pub
        })
    }
    fmt.println()



    candidates : []Candidate = {
        Candidate{ id = 67, fullname = "Petro Poroshenko", votes = 0 },
        Candidate{ id = 69, fullname = "Amogus",           votes = 0 },
    }



    if false {
        payload, ok1 := rsa.encrypt(&people[0].key_pub, { 1, 2, 3 })
        fmt.println(len(payload), ok1)

        test, ok2 := rsa.encrypt_long(&people[0].key_pub, payload)
        fmt.println(len(test), ok2)

        result, ok3 := rsa.decrypt_long(&people[0].key_prv, test)
        fmt.println(len(result), ok3)

        restore, ok4 := rsa.decrypt(&people[0].key_prv, result)
        fmt.println(restore, ok4)
    }



    fmt.printfln("VOTING STARTED")
    ballots : [dynamic][]u8
    for &p, personId in people {
        candidate := rand.choice(candidates)
        ballot := Ballot{ candidate_id = candidate.id }

        bytes : []u8 = slice.bytes_from_ptr(&ballot, size_of(Ballot))
        bytes = slice.clone(bytes)

        for round in 0 ..< ROUND_COUNT {
            #reverse for &v, voterId in voters {
                if voterId == personId {
                    salt := rand.uint64()
                    inject_at(&p.rememberedSalts, 0, salt)

                    saltedBytes : [dynamic]u8
                    append(&saltedBytes, ..slice.bytes_from_ptr(&salt, size_of(u64)))
                    append(&saltedBytes, ..bytes)

                    delete(bytes)
                    bytes = saltedBytes[:]
                }

                next, ok := rsa.encrypt_long(&v.key_pub, bytes)
                if !ok {
                    fmt.println("FATAL: failed encryption")
                }

                delete(bytes)
                bytes = next
            }
        }

        append(&ballots, bytes)
    }


    lastSignature : []u8

    fmt.println(len(ballots[0]))

    for round in 0 ..< ROUND_COUNT {
        for &p, personId in people {
            if !(round == 0 && personId == 0) {
                defer delete(lastSignature)

                voterId := personId == 0 ? len(voters) : personId
                voterId -= 1

                buffer : [dynamic]u8
                defer delete(buffer)
                for &b in ballots { append(&buffer, ..b) }

                result := rsa.verify(&voters[voterId].key_pub, buffer[:], lastSignature)
                if !result {
                    fmt.println("FATAL: signature bad")
                }
            }

            for &b in ballots {
                uncovered, ok := rsa.decrypt_long(&p.key_prv, b)
                if !ok {
                    fmt.println("FATAL: failed decryption")
                }

                delete(b)
                b = uncovered
            }

            found := false
            salt := p.rememberedSalts[round]
            for &b in ballots {
                if !slice.has_prefix(b, slice.bytes_from_ptr(&salt, size_of(u64))) { continue }

                found = true

                unsalted := slice.clone(b[size_of(u64):])
                delete(b)
                b = unsalted

                break
            }

            fmt.println(found)

            rand.shuffle(ballots[:])

            buffer : [dynamic]u8
            defer delete(buffer)
            for &b in ballots { append(&buffer, ..b) }
            lastSignature = rsa.sign(&p.key_prv, buffer[:])
        }
    }

    for &b in ballots {
        if len(b) != size_of(Ballot) {
            fmt.println("FATAL: Ballot is bad")
            continue
        }

        ballot := (cast(^Ballot)raw_data(b))^
        fmt.println(ballot)
    }
}
