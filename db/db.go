package db

import (
	"context"
	"log"
	"time"

	"github.com/Wee-code-Golang-Dojo/todo-manager/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

const (
	DbName         = "tasksdb"
	TaskCollection = "tasks"
	UserCollection = "users"
)

var dbClient *mongo.Client

func init() {
	// connect to the database
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatalf("Could not connect to the db: %v\n", err)
	}

	dbClient = client
	err = dbClient.Ping(ctx, readpref.Primary())
	if err != nil {
		log.Fatalf("MOngo db not available: %v\n", err)
	}
}

func CreateTask(task *models.Task) (*models.Task, error) {
	_, err := dbClient.Database(DbName).Collection(TaskCollection).InsertOne(context.Background(), task)

	return task, err
}

func GetSingleTask(taskId string) (*models.Task, error) {
	var task models.Task
	query := bson.M{
		"id": taskId,
	}
	err := dbClient.Database(DbName).Collection(TaskCollection).FindOne(context.Background(), query).Decode(&task)
	if err != nil {
		return nil, err
	}

	return &task, nil
}

func GetAllTasks(owner string) ([]models.Task, error) {
	var tasks []models.Task
	query := bson.M{
		"owner": owner,
	}
	cursor, err := dbClient.Database(DbName).Collection(TaskCollection).Find(context.Background(), query)
	if err != nil {
		return nil, err
	}

	err = cursor.All(context.Background(), &tasks)
	if err != nil {
		return nil, err
	}

	return tasks, nil
}

func UpdateTask(taskId, name, desc string) error {
	filterQuery := bson.M{
		"id": taskId,
	}

	updateQuery := bson.M{
		"$set": bson.M{
			"name":        name,
			"description": desc,
		},
	}

	_, err := dbClient.Database(DbName).Collection(TaskCollection).UpdateOne(context.Background(), filterQuery, updateQuery)
	if err != nil {
		return err
	}

	return nil
}

func DeleteTask(taskId, owner string) error {
	query := bson.M{
		"id":    taskId,
		"owner": owner,
	}
	_, err := dbClient.Database(DbName).Collection(TaskCollection).DeleteOne(context.Background(), query)
	if err != nil {
		return err
	}
	return nil
}

func GetUserByEmail(email string) (*models.User, error) {
	var user models.User
	query := bson.M{
		"email": email,
	}
	err := dbClient.Database(DbName).Collection(UserCollection).FindOne(context.Background(), query).Decode(&user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func CheckUserExists(email string) bool {
	query := bson.M{
		"email": email,
	}

	// search for duplicate users by email
	count, err := dbClient.Database(DbName).Collection(UserCollection).CountDocuments(context.Background(), query)
	if err != nil {
		return false
	}

	// if the count is greater than zero that means a user exists already with that email
	if count > 0 {
		return true
	}

	return false
}

func GetAllUsers() ([]models.User, error) {
	var users []models.User

	cursor, err := dbClient.Database(DbName).Collection(UserCollection).Find(context.Background(), bson.M{})
	if err != nil {
		return nil, err
	}

	err = cursor.All(context.Background(), &users)
	if err != nil {
		return nil, err
	}

	return users, nil
}

func CreateUser(user *models.User) (*models.User, error) {
	_, err := dbClient.Database(DbName).Collection(UserCollection).InsertOne(context.Background(), user)

	return user, err
}
