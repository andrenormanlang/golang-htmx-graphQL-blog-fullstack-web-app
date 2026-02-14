package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"blogflex/internal/database"
	"blogflex/views"

	"github.com/a-h/templ"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"

	"blogflex/internal/auth"
	"blogflex/internal/helpers"
	"blogflex/internal/models"
)

var store = sessions.NewCookieStore([]byte("your-very-secret-key"))

func ValidateURL(imagePath string) bool {
	_, err := url.ParseRequestURI(imagePath)
	return err == nil
}

func parseGraphQLTime(value interface{}) time.Time {
	timeStr, ok := value.(string)
	if !ok || strings.TrimSpace(timeStr) == "" {
		return time.Time{}
	}

	if parsed, err := time.Parse(time.RFC3339, timeStr); err == nil {
		return parsed
	}

	if parsed, err := time.Parse("2006-01-02T15:04:05", timeStr); err == nil {
		return parsed
	}

	return time.Time{}
}

func MainPageHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	userID := session.Values["userID"]
	loggedIn := userID != nil

	query := `
query {
  blogs(
    order_by: [
      { posts_aggregate: { max: { updated_at: desc_nulls_last } } }
      { posts_aggregate: { max: { created_at: desc } } }
      { updated_at: desc_nulls_last }
      { created_at: desc }
    ]
  ) {
    id
    name
    description
    image_path
    created_at
    updated_at
    user {
      username
    }
    posts(order_by: [{updated_at: desc_nulls_last}, {created_at: desc}], limit: 1) {
      id
      title
      created_at
      updated_at
    }
  }
}
`
	result, err := database.ExecuteGraphQL(query, nil)
	if err != nil {
		log.Printf("Failed to fetch blogs: %v", err)
		http.Error(w, "Failed to fetch blogs", http.StatusInternalServerError)
		return
	}

	blogsData, ok := result["blogs"].([]interface{})
	if !ok {
		log.Printf("Invalid data format for blogs: %v", result)
		http.Error(w, "Invalid data format for blogs", http.StatusInternalServerError)
		return
	}

	var blogs []models.Blog
	for _, blogData := range blogsData {
		blogMap, ok := blogData.(map[string]interface{})
		if !ok {
			log.Printf("Invalid data format for blogData: %v", blogData)
			continue
		}

		userMap, ok := blogMap["user"].(map[string]interface{})
		if !ok {
			log.Printf("Invalid data format for user: %v", blogMap["user"])
			continue
		}

		var imagePath string
		if blogMap["image_path"] != nil {
			imagePath, ok = blogMap["image_path"].(string)
			if !ok {
				log.Printf("image_path is not a string: %v", blogMap["image_path"])
				imagePath = ""
			} else if !ValidateURL(imagePath) {
				log.Printf("Invalid URL for image_path: %s", imagePath)
				imagePath = ""
			}
		}

		var latestPost *models.Post
		posts, ok := blogMap["posts"].([]interface{})
		if ok && len(posts) > 0 {
			postMap, ok := posts[0].(map[string]interface{})
			if !ok {
				log.Printf("Invalid data format for post: %v", posts[0])
				continue
			}

			postCreatedAt := parseGraphQLTime(postMap["created_at"])
			postUpdatedAt := parseGraphQLTime(postMap["updated_at"])
			if postUpdatedAt.IsZero() {
				postUpdatedAt = postCreatedAt
			}

			latestPost = &models.Post{
				Title:              postMap["title"].(string),
				CreatedAt:          postCreatedAt,
				UpdatedAt:          postUpdatedAt,
				FormattedCreatedAt: helpers.FormatTime(postCreatedAt),
			}
		}

		createdAt := parseGraphQLTime(blogMap["created_at"])
		updatedAt := parseGraphQLTime(blogMap["updated_at"])
		if updatedAt.IsZero() {
			updatedAt = createdAt
		}

		blogs = append(blogs, models.Blog{
			ID:                 uint(blogMap["id"].(float64)),
			Name:               blogMap["name"].(string),
			Description:        blogMap["description"].(string),
			ImagePath:          imagePath,
			CreatedAt:          createdAt,
			UpdatedAt:          updatedAt,
			FormattedCreatedAt: helpers.FormatTime(createdAt),
			User: &models.User{
				Username: userMap["username"].(string),
			},
			LatestPost: latestPost,
		})
	}

	// Sort blogs by effective update date (latest post update -> blog update -> blog creation)
	sort.SliceStable(blogs, func(i, j int) bool {
		iUpdated := blogs[i].UpdatedAt
		if blogs[i].LatestPost != nil && blogs[i].LatestPost.UpdatedAt.After(iUpdated) {
			iUpdated = blogs[i].LatestPost.UpdatedAt
		}

		jUpdated := blogs[j].UpdatedAt
		if blogs[j].LatestPost != nil && blogs[j].LatestPost.UpdatedAt.After(jUpdated) {
			jUpdated = blogs[j].LatestPost.UpdatedAt
		}

		if iUpdated.Equal(jUpdated) {
			return blogs[i].CreatedAt.After(blogs[j].CreatedAt)
		}

		return iUpdated.After(jUpdated)
	})

	log.Printf("Blogs: %+v", blogs)

	component := views.MainPage(blogs, loggedIn)
	templ.Handler(component).ServeHTTP(w, r)
}

// ListUsersHandler handles listing all users
func ListUsersHandler(w http.ResponseWriter, r *http.Request) {
	query := `
        query {
            users {
                id
                username
                email
            }
        }
    `
	result, err := helpers.GraphQLRequest(query, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	users := result["data"].(map[string]interface{})["users"].([]interface{})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// GetUserHandler handles fetching a single user by ID
func GetUserHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	query := `
        query ($id: Int!) {
            users_by_pk(id: $id) {
                id
                username
                email
            }
        }
    `
	variables := map[string]interface{}{
		"id": id,
	}

	result, err := helpers.GraphQLRequest(query, variables)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	user := result["data"].(map[string]interface{})["users_by_pk"]
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func SignUpHandler(w http.ResponseWriter, r *http.Request) {
	var user models.User
	var blogName, blogDescription, blogImagePath string

	// Limit the size of the request body to prevent large uploads
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20+512) // 10 MB max file size + 512 bytes

	// Parse the multipart form data
	err := r.ParseMultipartForm(10 << 20) // 10 MB max file size
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Access the form fields
	user.Username = r.FormValue("username")
	user.Email = r.FormValue("email")
	user.Password = r.FormValue("password")
	blogName = r.FormValue("blogName")
	blogDescription = r.FormValue("blogDescription")

	// Check if username already exists
	checkUsernameQuery := `
        query CheckUsernameExists($username: String!) {
            users(where: {username: {_eq: $username}}) {
                id
            }
        }
    `
	checkUsernameVariables := map[string]interface{}{
		"username": user.Username,
	}

	checkUsernameResult, err := database.ExecuteGraphQL(checkUsernameQuery, checkUsernameVariables)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	users := checkUsernameResult["users"].([]interface{})
	if len(users) > 0 {
		http.Error(w, "Username already exists, please enter another username", http.StatusConflict)
		return
	}

	// Check if email already exists
	checkEmailQuery := `
        query CheckEmailExists($email: String!) {
            users(where: {email: {_eq: $email}}) {
                id
            }
        }
    `
	checkEmailVariables := map[string]interface{}{
		"email": user.Email,
	}

	checkEmailResult, err := database.ExecuteGraphQL(checkEmailQuery, checkEmailVariables)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	users = checkEmailResult["users"].([]interface{})
	if len(users) > 0 {
		http.Error(w, "Email already exists, please use another email", http.StatusConflict)
		return
	}

	// Handle the uploaded file
	file, handler, err := r.FormFile("blogImage")
	if err == nil {
		defer file.Close()
		// Generate a unique file name and upload to Google Cloud Storage
		fileName := fmt.Sprintf("%s%s", uuid.New().String(), filepath.Ext(handler.Filename))
		blogImagePath, err = helpers.UploadFileToCloudinary(file, fileName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Hash the password before storing it
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	user.Password = string(hashedPassword)

	// Insert user into Hasura
	mutation := `
        mutation CreateUser($username: String!, $email: String!, $password: String!) {
            insert_users_one(object: {username: $username, email: $email, password: $password}) {
                id
                username
                email
            }
        }
    `
	variables := map[string]interface{}{
		"username": user.Username,
		"email":    user.Email,
		"password": user.Password,
	}

	data, err := database.SendGraphQLRequest(mutation, variables)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Extract the user ID from the GraphQL response
	userData := data["insert_users_one"].(map[string]interface{})
	userID := userData["id"].(string)

	// Create a blog for the new user
	blogMutation := `
        mutation CreateBlog($user_id: uuid!, $name: String!, $description: String!, $image_path: String) {
            insert_blogs_one(object: {user_id: $user_id, name: $name, description: $description, image_path: $image_path}) {
                id
            }
        }
    `
	blogVariables := map[string]interface{}{
		"user_id":     userID,
		"name":        blogName,
		"description": blogDescription,
		"image_path":  blogImagePath,
	}

	_, err = database.SendGraphQLRequest(blogMutation, blogVariables)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("User signed up: %s", user.Username)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Sign up successful! Please log in to continue.",
	})
}

// LoginHandler handles user login
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var user models.User

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Printf("Request Body: %s", body)

	contentType := r.Header.Get("Content-Type")

	if strings.Contains(contentType, "application/json") {
		err = json.Unmarshal(body, &user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		values, err := url.ParseQuery(string(body))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		user.Username = values.Get("username")
		user.Password = values.Get("password")
	} else {
		http.Error(w, "Unsupported content type", http.StatusUnsupportedMediaType)
		return
	}

	query := `
        query GetUser($username: String!) {
            users(where: {username: {_eq: $username}}) {
                id
                username
                password
            }
        }
    `
	variables := map[string]interface{}{
		"username": user.Username,
	}

	result, err := helpers.GraphQLRequest(query, variables)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	users := result["data"].(map[string]interface{})["users"].([]interface{})
	if len(users) == 0 {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	dbUser := users[0].(map[string]interface{})

	// Compare the stored hashed password with the provided password
	err = bcrypt.CompareHashAndPassword([]byte(dbUser["password"].(string)), []byte(user.Password))
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Convert the id to a string
	userID := fmt.Sprintf("%v", dbUser["id"])

	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &auth.Claims{
		UserID:   userID,
		Username: dbUser["username"].(string),
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(auth.JwtKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session, _ := store.Get(r, "session-name")
	session.Values["token"] = tokenString
	session.Values["userID"] = userID // Store the user ID in the session
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}

	log.Printf("User logged in: %s", dbUser["username"])

	blogQuery := `
        query GetUserBlog($user_id: uuid!) {
            blogs(where: {user_id: {_eq: $user_id}}) {
                id
            }
        }
    `
	blogVariables := map[string]interface{}{
		"user_id": userID,
	}

	blogResult, err := helpers.GraphQLRequest(blogQuery, blogVariables)
	if err != nil {
		http.Error(w, "User does not have a blog", http.StatusBadRequest)
		return
	}

	blogs := blogResult["data"].(map[string]interface{})["blogs"].([]interface{})
	if len(blogs) == 0 {
		http.Error(w, "User does not have a blog", http.StatusBadRequest)
		return
	}

	blogID := fmt.Sprintf("%v", blogs[0].(map[string]interface{})["id"])

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"redirect": fmt.Sprintf("/blogs/%s", blogID),
	})
}

// LogoutHandler handles user logout
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")

	// Clear session values
	session.Values["token"] = ""
	session.Values["userID"] = ""
	session.Options.MaxAge = -1 // This will delete the session

	// Save the session
	session.Save(r, w)

	// Invalidate the session token cookie
	cookie := &http.Cookie{
		Name:     "session-name",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)

	// Redirect to the main page
	w.Header().Set("HX-Redirect", "/")
	w.WriteHeader(http.StatusOK)
}
