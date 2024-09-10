package management

import (
	"log"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Peer struct {
	Id         string `gorm:"column:id;primaryKey"`
	Username   string `gorm:"column:username;unique"`
	Ip_address string `gorm:"column:ip_address"`
	Wg_pubkey  string `gorm:"column:wg_pubkey"`
	Created_at string `gorm:"column:created_at"`
	Privilege  int32  `gorm:"column:privilege"`
}

var db *gorm.DB

func openDb(dbName string) {
	var err error
	db, err = gorm.Open(sqlite.Open(dbName), &gorm.Config{})
	if err != nil {
		panic(err)
	}
}

func migrateSchema(models ...interface{}) {
	err := db.AutoMigrate(models...)
	if err != nil {
		log.Println(err)
	}
}

func createPeer(peer *Peer) {
	if result := db.Create(&peer); result.Error != nil {
		log.Printf("[Failed to create peer %s]", result.Error)
	}
}

/*
func queryAllPeer() []Peer {
	var peers []Peer
	if result := db.Find(&peers); result.Error != nil {
		log.Println(result.Error)
	}
	return peers
}

func queryPeer(Id string) *Peer {
	var peer Peer
	if result := db.Where("id = ?", Id).First(&peer); result.Error != nil {
		log.Println(result.Error)
	}
	return &peer
}
*/
