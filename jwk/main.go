package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

func main() {
	ExampleJWK_ParseToken()
}

func ExampleJWK_Usage() {
	// Use jwk.AutoRefresh if you intend to keep reuse the JWKS over and over
	set, err := jwk.Fetch(context.Background(), "https://raw.githubusercontent.com/yanuar-nc/yanuar-nc/main/jwk.json")
	if err != nil {
		log.Printf("failed to parse JWK: %s", err)
		return
	}

	// Key sets can be serialized back to JSON
	{
		jsonbuf, err := json.Marshal(set)
		if err != nil {
			log.Printf("failed to marshal key set into JSON: %s", err)
			return
		}
		log.Printf("%s", jsonbuf)
	}
	var keyset jwk.Set
	keyset = jwk.NewSet()

	for it := set.Iterate(context.Background()); it.Next(context.Background()); {
		pair := it.Pair()
		key := pair.Value.(jwk.Key)

		var rawkey interface{} // This is the raw key, like *rsa.PrivateKey or *ecdsa.PrivateKey
		if err := key.Raw(&rawkey); err != nil {
			log.Printf("failed to create public key: %s", err)
			return
		}
		// Use rawkey for jws.Verify() or whatever.
		_ = rawkey

		// You can create jwk.Key from a raw key, too
		fromRawKey, err := jwk.New(rawkey)
		if err != nil {
			log.Printf("failed to acquire raw key from jwk.Key: %s", err)
			return
		}
		log.Printf("%s\n", key.KeyID())
		// Keys can be serialized back to JSON
		jsonbuf, err := json.Marshal(key)
		if err != nil {
			log.Printf("failed to marshal key into JSON: %s", err)
			return
		}
		// log.Printf("%s", jsonbuf)
		{
			// Remember, the key must have the proper "kid", and "alg"
			// If your key does not have "alg", see jwt.InferAlgorithmFromKey()
			// fromRawKey.Set(jwk.AlgorithmKey, key.Algorithm())
			// fromRawKey.Set(jwk.KeyIDKey, key.KeyID())

			keyset.Add(key)
		}

		// If you know the underlying Key type (RSA, EC, Symmetric), you can
		// create an empty instance first
		//    key := jwk.NewRSAPrivateKey()
		// ..and then use json.Unmarshal
		//    json.Unmarshal(key, jsonbuf)
		//
		// but if you don't know the type first, you have an abstract type
		// jwk.Key, which can't be used as the first argument to json.Unmarshal
		//
		// In this case, use jwk.Parse()
		x, err := jwk.Parse(jsonbuf)
		if err != nil {
			log.Printf("failed to parse json: %s", err)
			return
		}
		_ = x
		_ = fromRawKey
	}
	buf, err := json.MarshalIndent(keyset, "", "  ")
	if err != nil {
		fmt.Printf("failed to marshal key into JSON: %s\n", err)
		return
	}
	fmt.Printf("%s\n", buf)

	{
		token, err := jwt.Parse(
			[]byte("eyJhbGciOiJSUzI1NiIsImtpZCI6IjY2NjAwMDAwMSIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7InVzZSI6ImFzdXV1In0sImlhdCI6MTY3NjQ1NjA2MywiaXNzIjoiZ2l0aHViLmNvbS9sZXN0cnJhdC1nby9qd3gifQ.e6AGPS3iJrafwY74sGO7-5trndm7WCuOIsYX3hoDwOZ2M1cY8FSDoV83u4wrwq1qx9GujDE3PlCelKcHhxatD9VB1qDyO3xFXZHUkGsAo6PaykKHlasqw9-5g0eBrp3vl2JEJAl4mYPe_wx1s-OAwR7Sa-vSp17-pgKxk9ghaNJhDYRVnm2oizeLJ3nQL7aJowVnEK97rOczTaEOAlcxlN5LKETNkeeybjZPsvfDv2Ylc9UtP8CnPsXWtwPyRoT3wfD9K1HpkX8hIU9OK_pXsBJX9-1XKsIWH8o7mDm7OtePuyHU1LYVq0HZasDp8alJ7OJPoryM1tGudBl208fndw"),
			// Tell the parser that you want to use this keyset
			jwt.WithKeySet(keyset),
			// Uncomment the following option if you know your key does not have an "alg"
			// field (which is apparently the case for Azure tokens)
			// jwt.InferAlgorithmFromKey(true),
		)
		if err != nil {
			fmt.Printf("failed to parse payload: %s\n", err)
		}

		buf, err := json.MarshalIndent(token, "", "  ")
		if err != nil {
			fmt.Printf("failed to generate JSON: %s\n", err)
			return
		}
		fmt.Printf("%s\n", buf)
	}
	// OUTPUT:
}

func ExampleJWK_FromPriv() {
	var (
		privkey interface{}
		signed  []byte
		// bytes       []byte
		// err         error
		key, jwkKey jwk.Key
		keyset      jwk.Set
	)
	const keyID = "666000001"
	/*
		// GET PRIVATE KEY FROM FILES
		{
			bytes, err = ioutil.ReadFile("private-key.pem")
			if err != nil {
				panic(err)
			}
			privkey, err = ssh.ParseRawPrivateKey(bytes)
			if err != nil {
				panic(err)
			}

			key, err = jwk.New(privkey)
			if err != nil {
				fmt.Printf("failed to create RSA key: %s\n", err)
				return
			}

			if _, ok := key.(jwk.RSAPrivateKey); !ok {
				fmt.Printf("expected jwk.RSAPrivateKey, got %T\n", key)
				return
			}
			key.Set(jwk.AlgorithmKey, "RS256")
			key.Set(jwk.KeyIDKey, "666000001")
			key.Set(jwk.KeyUsageKey, "sig")

			buf, err := json.MarshalIndent(key, "", "  ")
			if err != nil {
				fmt.Printf("failed to marshal key into JSON: %s\n", err)
				return
			}
			fmt.Printf("PRIVATE KEY SET: \n%s\n", buf)

		}
	*/

	// SIGNED TOKEN
	{
		set, err := jwk.Fetch(context.Background(), "https://raw.githubusercontent.com/yanuar-nc/yanuar-nc/main/jwk-priv.json")
		if err != nil {
			log.Printf("failed to parse JWK: %s", err)
			return
		}

		for it := set.Iterate(context.Background()); it.Next(context.Background()); {
			pair := it.Pair()
			key = pair.Value.(jwk.Key)

			var rawkey interface{} // This is the raw key, like *rsa.PrivateKey or *ecdsa.PrivateKey
			if err := key.Raw(&rawkey); err != nil {
				log.Printf("failed to create public key: %s", err)
				return
			}
			{
				jwkKey, err = jwk.New(rawkey)
				if err != nil {
					log.Printf("failed to create JWK key: %s", err)
					return
				}
				jwkKey.Set(jwk.KeyIDKey, keyID)
			}

		}
	}

	{
		// Build a JWT!
		tok, err := jwt.NewBuilder().
			Issuer(`github.com/lestrrat-go/jwx`).
			IssuedAt(time.Now()).
			Claim("data", map[string]string{"use": "asuuu"}).
			Build()
		if err != nil {
			fmt.Printf("failed to build token: %s\n", err)
			return
		}

		// Sign a JWT!
		signed, err = jwt.Sign(tok, jwa.RS256, jwkKey)
		if err != nil {
			fmt.Printf("failed to sign token: %s\n", err)
			return
		}
		fmt.Println(string(signed)) // eyJhbGciOiJSUzI1NiIsImtpZCI6IjBYMjlBIiwidHlwIjoiSldUIn0.eyJkYXRhIjp7InVzZSI6ImFzdXV1In0sImlhdCI6MTY3NjQwNDE1OCwiaXNzIjoiZ2l0aHViLmNvbS9sZXN0cnJhdC1nby9qd3gifQ.M7rRvFG85Ywkg0h_DdAAhvCXm4WaPAl8U8d7z70lCTht69rgoMmKrU-UEGXQKIWAi2wDfo5psHXn0ROALd5ynPNNVz-74vNG3SCwiy2RaapZZWQeFufgZpbZTTJk4l9S5tpvPa7jAsEl05bjz4Jy6qC_iJD8CWZizJ4o6H3yEJZxhGCtbaFS2gIpeDS1QwbL972c84aA6V856pWqPMDlXPNh_QmYhN7833XwbGYsL_GoN7NdWLOOCXaj4RRpyJCohlrBkB0QFvSoeoyTVpwHrrJ-AKNXI7e8gTaSkhwcPPIJ2-_x0HWc_D47-s2Ppc0CxmT0c_whnGHZS8Bw4q2h5nbBP__i_VsZCniknEwGD5jR_mo8eKWUsSciACdcBxb2uUNSCm-G7ewpE2K0JAkIRTTZJhgFkrzBe8axdfYQcs93CrUDJlPtPgBBAq24Tzn7PTtzrNQ8gOXF9gBZ39g_UoKjf8aQXLk1DuhhL3iDED12ljyx8yjAoYkZujtyVfzR
	}

	// GET PUBLIC KEY
	{
		// k := NewRSAPublicKey()
		pkey := privkey.(*rsa.PrivateKey)
		pubKey, err := jwk.New(pkey.PublicKey)
		if err != nil {
			fmt.Printf("failed to create JWK: %s\n", err)
			return
		}
		// Remember, the key must have the proper "kid", and "alg"
		// If your key does not have "alg", see jwt.InferAlgorithmFromKey()
		// pubKey.Set(jwk.AlgorithmKey, jwa.RS256)
		pubKey.Set(jwk.KeyIDKey, keyID)

		keyset = jwk.NewSet()
		keyset.Add(pubKey)

		buf, err := json.MarshalIndent(keyset, "", "  ")
		if err != nil {
			fmt.Printf("failed to marshal key into JSON: %s\n", err)
			return
		}
		fmt.Printf("PUBLIC KEY SET: \n%s\n", buf)
	}

	{ // Actual verification:
		// FINALLY. This is how you Parse and verify the payload.
		// Key IDs are automatically matched.
		// There was a lot of code above, but as a consumer, below is really all you need
		// to write in your code
		token, err := jwt.Parse(
			signed,
			// Tell the parser that you want to use this keyset
			jwt.WithKeySet(keyset),
			// Uncomment the following option if you know your key does not have an "alg"
			// field (which is apparently the case for Azure tokens)
			// jwt.InferAlgorithmFromKey(true),
		)
		if err != nil {
			fmt.Printf("failed to parse payload: %s\n", err)
		}

		buf, err := json.MarshalIndent(token, "", "  ")
		if err != nil {
			fmt.Printf("failed to generate JSON: %s\n", err)
			return
		}
		fmt.Printf("%s\n", buf)
	}
	// PublicKey is omitted for brevity
}

func ExampleJWK_New() {
	// New returns different underlying types of jwk.Key objects
	// depending on the input value.
	var key jwk.Key
	var err error
	const keyID = "666000001"
	// []byte -> jwk.SymmetricKey
	{
		raw := []byte("Lorem Ipsum")
		key, err = jwk.New(raw)
		if err != nil {
			fmt.Printf("failed to create symmetric key: %s\n", err)
			return
		}
		if _, ok := key.(jwk.SymmetricKey); !ok {
			fmt.Printf("expected jwk.SymmetricKey, got %T\n", key)
			return
		}
	}

	// *rsa.PrivateKey -> jwk.RSAPrivateKey
	// *rsa.PublicKey  -> jwk.RSAPublicKey
	{
		raw, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			fmt.Printf("failed to generate new RSA private key: %s\n", err)
			return
		}

		key, err = jwk.New(raw)
		if err != nil {
			fmt.Printf("failed to create RSA key: %s\n", err)
			return
		}
		if _, ok := key.(jwk.RSAPrivateKey); !ok {
			fmt.Printf("expected jwk.RSAPrivateKey, got %T\n", key)
			return
		}

		key.Set(jwk.AlgorithmKey, jwa.RS256)
		key.Set(jwk.KeyIDKey, keyID)

		buf, err := json.MarshalIndent(key, "", "  ")
		if err != nil {
			fmt.Printf("failed to marshal key into JSON: %s\n", err)
			return
		}
		fmt.Printf("PRIVATE KEY: \n%s\n", buf)
		// PublicKey is omitted for brevity

		// GET PUBLIC KEY

		// k := NewRSAPublicKey()
		pubKey, err := jwk.New(raw.PublicKey)
		if err != nil {
			fmt.Printf("failed to create JWK: %s\n", err)
			return
		}
		// Remember, the key must have the proper "kid", and "alg"
		// If your key does not have "alg", see jwt.InferAlgorithmFromKey()
		pubKey.Set(jwk.AlgorithmKey, jwa.RS256)
		pubKey.Set(jwk.KeyIDKey, keyID)

		keyset := jwk.NewSet()
		keyset.Add(pubKey)

		buf, err = json.MarshalIndent(keyset, "", "  ")
		if err != nil {
			fmt.Printf("failed to marshal key into JSON: %s\n", err)
			return
		}
		fmt.Printf("PUBLIC KEY: \n%s\n", buf)

	}

	// *ecdsa.PrivateKey -> jwk.ECDSAPrivateKey
	// *ecdsa.PublicKey  -> jwk.ECDSAPublicKey
	{
		raw, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			fmt.Printf("failed to generate new ECDSA private key: %s\n", err)
			return
		}

		key, err = jwk.New(raw)
		if err != nil {
			fmt.Printf("failed to create ECDSA key: %s\n", err)
			return
		}
		if _, ok := key.(jwk.ECDSAPrivateKey); !ok {
			fmt.Printf("expected jwk.ECDSAPrivateKey, got %T\n", key)
			return
		}
		// PublicKey is omitted for brevity
	}

	// OUTPUT:
}

func ExampleJWK_SignByKeysFromURL() {
	// Get private key
	jwkVal, err := getPrivateFromJWKS()
	if err != nil {
		log.Printf("failed get private from jwks: %s", err)
	}

	// Build a JWT!
	tok, err := jwt.NewBuilder().
		Issuer(`github.com/lestrrat-go/jwx`).
		IssuedAt(time.Now()).
		Claim("data", map[string]string{"use": "asuuu"}).
		Build()
	if err != nil {
		fmt.Printf("failed to build token: %s\n", err)
		return
	}

	// Sign a JWT!
	signed, err := jwt.Sign(tok, jwa.RS256, jwkVal)
	if err != nil {
		fmt.Printf("failed to sign token: %s\n", err)
		return
	}
	fmt.Println(string(signed)) // eyJhbGciOiJSUzI1NiIsImtpZCI6IjBYMjlBIiwidHlwIjoiSldUIn0.eyJkYXRhIjp7InVzZSI6ImFzdXV1In0sImlhdCI6MTY3NjQwNDE1OCwiaXNzIjoiZ2l0aHViLmNvbS9sZXN0cnJhdC1nby9qd3gifQ.M7rRvFG85Ywkg0h_DdAAhvCXm4WaPAl8U8d7z70lCTht69rgoMmKrU-UEGXQKIWAi2wDfo5psHXn0ROALd5ynPNNVz-74vNG3SCwiy2RaapZZWQeFufgZpbZTTJk4l9S5tpvPa7jAsEl05bjz4Jy6qC_iJD8CWZizJ4o6H3yEJZxhGCtbaFS2gIpeDS1QwbL972c84aA6V856pWqPMDlXPNh_QmYhN7833XwbGYsL_GoN7NdWLOOCXaj4RRpyJCohlrBkB0QFvSoeoyTVpwHrrJ-AKNXI7e8gTaSkhwcPPIJ2-_x0HWc_D47-s2Ppc0CxmT0c_whnGHZS8Bw4q2h5nbBP__i_VsZCniknEwGD5jR_mo8eKWUsSciACdcBxb2uUNSCm-G7ewpE2K0JAkIRTTZJhgFkrzBe8axdfYQcs93CrUDJlPtPgBBAq24Tzn7PTtzrNQ8gOXF9gBZ39g_UoKjf8aQXLk1DuhhL3iDED12ljyx8yjAoYkZujtyVfzR
}

func ExampleJWK_ParseToken() {
	var signed = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjY2NjAwMDAwMSIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7InVzZSI6ImFzdXV1In0sImlhdCI6MTY3NjQ1NjA2MywiaXNzIjoiZ2l0aHViLmNvbS9sZXN0cnJhdC1nby9qd3gifQ.e6AGPS3iJrafwY74sGO7-5trndm7WCuOIsYX3hoDwOZ2M1cY8FSDoV83u4wrwq1qx9GujDE3PlCelKcHhxatD9VB1qDyO3xFXZHUkGsAo6PaykKHlasqw9-5g0eBrp3vl2JEJAl4mYPe_wx1s-OAwR7Sa-vSp17-pgKxk9ghaNJhDYRVnm2oizeLJ3nQL7aJowVnEK97rOczTaEOAlcxlN5LKETNkeeybjZPsvfDv2Ylc9UtP8CnPsXWtwPyRoT3wfD9K1HpkX8hIU9OK_pXsBJX9-1XKsIWH8o7mDm7OtePuyHU1LYVq0HZasDp8alJ7OJPoryM1tGudBl208fndw"
	keyset, err := getPublicFromJWKS()
	if err != nil {
		log.Printf("fail get key set, err: %s", err)
	}
	// FINALLY. This is how you Parse and verify the payload.
	// Key IDs are automatically matched.
	// There was a lot of code above, but as a consumer, below is really all you need
	// to write in your code
	token, err := jwt.Parse(
		[]byte(signed),
		jwt.WithKeySet(keyset),
	)
	if err != nil {
		fmt.Printf("failed to parse payload: %s\n", err)
	}

	buf, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		fmt.Printf("failed to generate JSON: %s\n", err)
		return
	}
	fmt.Printf("%s\n", buf)
}

func getPrivateFromJWKS() (jwk.Key, error) {
	var (
		key, jwkKey jwk.Key
	)
	const keyID = "666000001"
	set, err := jwk.Fetch(context.Background(), "https://raw.githubusercontent.com/yanuar-nc/yanuar-nc/main/jwk-priv.json")
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK: %s", err)
	}

	for it := set.Iterate(context.Background()); it.Next(context.Background()); {
		pair := it.Pair()
		key = pair.Value.(jwk.Key)

		var rawkey interface{} // This is the raw key, like *rsa.PrivateKey or *ecdsa.PrivateKey
		if err := key.Raw(&rawkey); err != nil {
			return nil, fmt.Errorf("failed to create public key: %s", err)
		}
		{
			jwkKey, err = jwk.New(rawkey)
			if err != nil {
				return nil, fmt.Errorf("failed to create JWK key: %s", err)
			}
			jwkKey.Set(jwk.KeyIDKey, keyID)
		}
	}
	return jwkKey, nil
}

func getPublicFromJWKS() (jwk.Set, error) {
	// Use jwk.AutoRefresh if you intend to keep reuse the JWKS over and over
	set, err := jwk.Fetch(context.Background(), "https://raw.githubusercontent.com/yanuar-nc/yanuar-nc/main/jwk.json")
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK: %s", err)
	}

	keyset := jwk.NewSet()

	for it := set.Iterate(context.Background()); it.Next(context.Background()); {
		pair := it.Pair()
		key := pair.Value.(jwk.Key)

		var rawkey interface{} // This is the raw key, like *rsa.PrivateKey or *ecdsa.PrivateKey
		if err := key.Raw(&rawkey); err != nil {
			return nil, fmt.Errorf("failed to create public key: %s", err)
		}
		keyset.Add(key)
	}

	return keyset, nil
}
