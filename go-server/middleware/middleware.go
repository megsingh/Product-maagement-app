package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"go-server/models"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

var productCollection *mongo.Collection
var userCollection *mongo.Collection
var SECRET_KEY = []byte("RESTAPI")

func init() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	atlasUrl := os.Getenv("DB_URL")
	db := os.Getenv("DB_NAME")
	productCollName := os.Getenv("DB_COLLECTION_PRODUCTS")
	userCollName := os.Getenv("DB_COLLECTION_USERS")

	clientOptions := options.Client().ApplyURI(atlasUrl)
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	err = client.Ping(context.TODO(), nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Connected to MongoDB!")

	productCollection = client.Database(db).Collection(productCollName)
	userCollection = client.Database(db).Collection(userCollName)
	fmt.Println("Collection instance created!")
}

func IsAuthorized(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization ")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		fmt.Println(r.Header.Get("Authorization"))
		authHeader := strings.Split(r.Header.Get("Authorization"), "Bearer ")
		fmt.Println("Auth Header: ", authHeader)
		if len(authHeader) != 2 {
			fmt.Println("Malformed token")
			json.NewEncoder(w).Encode("Malformed token")
		} else {
			jwtToken := authHeader[1]
			token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return []byte(SECRET_KEY), nil
			})

			if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
				ctx := context.WithValue(r.Context(), "props", claims)
				handler.ServeHTTP(w, r.WithContext(ctx))
			} else {
				fmt.Println(err)
				json.NewEncoder(w).Encode("unAuthorized")
			}
		}
	}
}

func UserRegister(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Max-Age", "600")

	var user models.User
	json.NewDecoder(r.Body).Decode(&user)

	var dbUser models.User
	userCollection.FindOne(context.Background(), bson.M{"email": user.Email}).Decode(&dbUser)
	if dbUser.Email != "" {
		json.NewEncoder(w).Encode("User Already Exists!")

	} else {
		hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.MinCost)
		if err != nil {
			log.Fatal(err)
		}
		user.Password = string(hash)

		result, err := userCollection.InsertOne(context.Background(), user)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("Inserted a Single user ", result.InsertedID)
		json.NewEncoder(w).Encode(result)
		return
	}

}

func UserLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Max-Age", "600")

	var user models.User
	var dbUser models.User

	json.NewDecoder(r.Body).Decode(&user)
	err := userCollection.FindOne(context.Background(), bson.M{"email": user.Email}).Decode(&dbUser)
	if err != nil {
		log.Fatal(err)
	}
	if dbUser.Email == "" {
		json.NewEncoder(w).Encode("User Does Not Exist!")
	} else {
		userPassword := []byte(user.Password)
		dbUserPassword := []byte(dbUser.Password)

		passwordErr := bcrypt.CompareHashAndPassword(dbUserPassword, userPassword)
		if passwordErr != nil {
			fmt.Println("Incorrect Password!")
			json.NewEncoder(w).Encode("Incorrect Password!")
			return
		}
		token, err := GenerateJWT(dbUser.ID.Hex())
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(token)
		json.NewEncoder(w).Encode(token)
	}

}

func GenerateJWT(id string) (string, error) {
	var mySigningKey = []byte(SECRET_KEY)
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)

	claims["authorized"] = true
	claims["id"] = id
	claims["exp"] = time.Now().Add(time.Hour * 7).Unix()

	tokenString, err := token.SignedString(mySigningKey)

	if err != nil {
		log.Fatalf("Something Went Wrong: %s", err.Error())
		return "", err
	}
	return tokenString, nil
}

func GetProducts(w http.ResponseWriter, r *http.Request) {
	//w.Header().Set("Access-Control-Max-Age", "600")

	props, _ := r.Context().Value("props").(jwt.MapClaims)
	id, _ := primitive.ObjectIDFromHex(props["id"].(string))
	filter := bson.M{"user": id}
	cursor, err := productCollection.Find(context.Background(), filter)
	if err != nil {
		log.Fatal(err)
	}

	var results []primitive.M
	for cursor.Next(context.Background()) {
		var result bson.M
		err := cursor.Decode(&result)
		if err != nil {
			log.Fatal(err)
		}
		results = append(results, result)

	}

	if err := cursor.Err(); err != nil {
		log.Fatal(err)
	}
	cursor.Close(context.Background())
	json.NewEncoder(w).Encode(results)
}

func AddProduct(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Max-Age", "600")

	var product models.Product
	product.Delivered = false
	props, _ := r.Context().Value("props").(jwt.MapClaims)
	id, _ := primitive.ObjectIDFromHex(props["id"].(string))
	product.User = id

	json.NewDecoder(r.Body).Decode(&product)
	result, err := productCollection.InsertOne(context.Background(), product)
	if err != nil {
		log.Fatal(err)
	}
	json.NewEncoder(w).Encode(result)
}

func UpdateProduct(w http.ResponseWriter, r *http.Request) {

	props, _ := r.Context().Value("props").(jwt.MapClaims)
	userId, _ := primitive.ObjectIDFromHex(props["id"].(string))
	params := mux.Vars(r)
	productId, _ := primitive.ObjectIDFromHex(params["id"])
	filter := bson.M{"_id": productId, "user": userId}
	update := bson.M{"$set": bson.M{"delivered": true}}
	result, err := productCollection.UpdateOne(context.Background(), filter, update)
	if err != nil {
		log.Fatal(err)
	}
	json.NewEncoder(w).Encode(result)
}

func DeleteProduct(w http.ResponseWriter, r *http.Request) {
	props, _ := r.Context().Value("props").(jwt.MapClaims)
	userId, _ := primitive.ObjectIDFromHex(props["id"].(string))
	params := mux.Vars(r)
	productId, _ := primitive.ObjectIDFromHex(params["id"])
	filter := bson.M{"_id": productId, "user": userId}
	result, err := productCollection.DeleteOne(context.Background(), filter)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Deleted Product", result.DeletedCount)
	json.NewEncoder(w).Encode(result)
}
