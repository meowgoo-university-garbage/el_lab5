package main

import "core:fmt"
import "core:slice"
import "core:math/rand"

import "core:math/big"

// import "core:crypto/rsa"
import "./rsa"
import "core:crypto/hash"

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
    person_id : u64,
    fullname : string,
    key_pub : rsa.Key_Public,
}







Ballot :: struct {
    candidate_id : u64,
}



main :: proc () {
    people : []Person = {
        Person{ id = 0, fullname = "Vitalya Gryb", country = .Ukraine, age = 23 },
        // Person{ id = 1, fullname = "Svitlana Zhizha", country = .Ukraine, age = 27 },
        // Person{ id = 2, fullname = "Zheka Zrada", country = .Ukraine, age = 19 },
        // Person{ id = 3, fullname = "Grzegorz Brzeczyszczykiewicz", country = .Ukraine, age = 153 },
        // Person{ id = 5, fullname = "Yaroslav Aboba", country = .Ukraine, age = 34 },
    }



    for &p in people {
        p.key_prv, p.key_pub = rsa.keygen()
        fmt.printfln("Generated private key for %v", p.fullname)
    }
    fmt.println()



    {
        payload, ok1 := rsa.encrypt(&people[0].key_pub, { 1, 2, 3 })
        fmt.println(len(payload), ok1)

        test, ok2 := rsa.encrypt_long(&people[0].key_pub, payload)
        fmt.println(len(test), ok2)

        result, ok3 := rsa.decrypt_long(&people[0].key_prv, test)
        fmt.println(len(result), ok3)

        restore, ok4 := rsa.decrypt(&people[0].key_prv, result)
        fmt.println(restore, ok4)
    }


    candidates : []Candidate = {
        Candidate{ fullname = "Petro Poroshenko", votes = 0 },
        Candidate{ fullname = "Amogus", votes = 0 },
    }
}
