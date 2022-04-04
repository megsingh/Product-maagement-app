package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type Product struct {
	ID        primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Title     string             `json:"title,omitempty"`
	Author    string             `json:"author,omitempty"`
	Delivered bool               `json:"delivered,omitempty"`
	User      primitive.ObjectID `json:"user,omitempty" bson:"user,omitempty"`
}

type User struct {
	ID       primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Name     string             `json:"name,omitempty" bson:"name,omitempty"`
	Email    string             `json:"email" gorm:"unique" validate:"required" bson:"email,required"`
	Password string             `json:"password" validate:"required"  bson:"password,required"`
}
