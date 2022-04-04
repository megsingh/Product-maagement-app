package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type Product struct {
	ID        primitive.ObjectID `bson:"_id,omitempty"`
	Title     string             `bson:"title,omitempty"`
	Author    string             `bson:"author,omitempty"`
	Delivered bool               `bson:"delivered,omitempty"`
	User      primitive.ObjectID `bson:"user,omitempty"`
}

type User struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"`
	Name     string             `bson:"name,omitempty"`
	Email    string             `bson:"email,required"`
	Password string             `bson:"password,required"`
}
