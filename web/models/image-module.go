package models

import (
	"gorm.io/gorm"
	"time"
)

type Image struct {
	gorm.Model
	ExpireDate time.Time `json:"expire_date"`
	ImageHash  string    `json:"image_hash"`
	ImageName  string    `json:"image_name"`
	IV         string    `json:"iv"`
	Salt       string    `json:"salt"`
}

func (i *Image) TableName() string {
	return "images"
}
