package handlers

import (
	"blogflex/internal/auth"
	"blogflex/internal/helpers"
	"blogflex/internal/models"
	"blogflex/views"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"blogflex/internal/database"
	"fmt"
	"path/filepath"

	"github.com/a-h/templ"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

// CreateBlogHandler handles creating a new blog
func CreateBlogHandler(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value("session").(*sessions.Session)
	userID := session.Values["userID"].(string)

	var blog struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		err = json.Unmarshal(body, &blog)
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
		blog.Name = values.Get("name")
		blog.Description = values.Get("description")
	} else {
		http.Error(w, "Unsupported content type", http.StatusUnsupportedMediaType)
		return
	}

	query := `
        mutation CreateBlog($name: String!, $description: String!, $user_id: uuid!) {
            insert_blogs_one(object: {name: $name, description: $description, user_id: $user_id}) {
                id
            }
        }
    `
	variables := map[string]interface{}{
		"name":        blog.Name,
		"description": blog.Description,
		"user_id":     userID,
	}

	result, err := helpers.GraphQLRequest(query, variables)
	if err != nil || len(result["errors"].([]interface{})) > 0 {
		http.Error(w, "Failed to create blog", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Header().Set("HX-Redirect", "/")
}

// BlogListHandler handles displaying a list of blogs
func BlogListHandler(w http.ResponseWriter, r *http.Request) {
	query := `
        query {
            blogs(order_by: [{updated_at: desc_nulls_last}, {created_at: desc}]) {
                id
                name
                description
                user {
                    username
                }
                created_at
                updated_at
            }
        }
    `

	result, err := helpers.GraphQLRequest(query, nil)
	if err != nil {
		log.Printf("Error fetching blogs: %v", err)
		http.Error(w, "Failed to fetch blogs: "+err.Error(), http.StatusInternalServerError)
		return
	}

	blogsData := result["data"].(map[string]interface{})["blogs"].([]interface{})
	var blogs []models.Blog
	for _, blogData := range blogsData {
		blogMap := blogData.(map[string]interface{})
		userMap := blogMap["user"].(map[string]interface{})

		blogs = append(blogs, models.Blog{
			ID:          uint(blogMap["id"].(float64)),
			Name:        blogMap["name"].(string),
			Description: blogMap["description"].(string),
			User: &models.User{
				Username: userMap["username"].(string),
			},
		})
	}

	component := views.BlogList(blogs)
	templ.Handler(component).ServeHTTP(w, r)
}

// BlogPageHandler handles displaying a single blog page with its posts
func BlogPageHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	blogID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid blog ID", http.StatusBadRequest)
		return
	}

	// Query to get blog details and posts
	blogQuery := `
        query GetBlogWithPosts($id: Int!) {
            blogs_by_pk(id: $id) {
                id
                name
                description
                user {
                    id
                    username
                }
                posts(order_by: [{updated_at: desc}, {created_at: desc}]) {
                    id
                    title
                    content
                    created_at
                    comments_aggregate {
                        aggregate {
                            count
                        }
                    }
                }
            }
        }
    `
	blogVariables := map[string]interface{}{
		"id": blogID,
	}

	blogResult, err := helpers.GraphQLRequest(blogQuery, blogVariables)
	if err != nil {
		log.Printf("Failed to fetch blog: %v", err)
		http.Error(w, "Failed to fetch blog", http.StatusInternalServerError)
		return
	}

	log.Printf("GraphQL blog result: %+v\n", blogResult)

	if blogResult["data"] == nil {
		log.Println("blogResult[data] is nil")
		http.Error(w, "Failed to fetch blog data", http.StatusInternalServerError)
		return
	}

	blogData, ok := blogResult["data"].(map[string]interface{})["blogs_by_pk"].(map[string]interface{})
	if !ok || blogData == nil {
		log.Println("blogData is nil or not a map")
		http.Error(w, "Failed to fetch blog data", http.StatusInternalServerError)
		return
	}

	var userMap map[string]interface{}
	if blogData["user"] != nil {
		userMap, ok = blogData["user"].(map[string]interface{})
		if !ok {
			userMap = map[string]interface{}{"id": "0", "username": "Unknown"}
		}
	} else {
		userMap = map[string]interface{}{"id": "0", "username": "Unknown"}
	}

	postsData, ok := blogData["posts"].([]interface{})
	if !ok {
		log.Println("postsData is nil or not a slice of interfaces")
		postsData = []interface{}{}
	}

	// Collect post IDs to fetch likes count
	var postIDs []int
	for _, postData := range postsData {
		postMap := postData.(map[string]interface{})
		postID := int(postMap["id"].(float64))
		postIDs = append(postIDs, postID)
	}

	var likesMap map[int]int
	if len(postIDs) > 0 {
		// Query to get likes count for the posts
		likesQuery := `
            query GetLikesCounts($post_ids: [Int!]!) {
                posts_with_likes(where: {post_id: {_in: $post_ids}}) {
                    post_id
                    likes_count
                }
            }
        `
		likesVariables := map[string]interface{}{
			"post_ids": postIDs,
		}

		likesResult, err := helpers.GraphQLRequest(likesQuery, likesVariables)
		if err != nil {
			log.Printf("Failed to fetch likes count: %v", err)
			http.Error(w, "Failed to fetch likes count", http.StatusInternalServerError)
			return
		}

		log.Printf("GraphQL likes result: %+v\n", likesResult)

		likesData, ok := likesResult["data"].(map[string]interface{})["posts_with_likes"].([]interface{})
		if !ok || likesData == nil {
			log.Printf("posts_with_likes is nil or not a slice: %v", likesResult["data"])
			http.Error(w, "Failed to fetch likes data", http.StatusInternalServerError)
			return
		}

		// Create a map of post IDs to likes count
		likesMap = make(map[int]int)
		for _, like := range likesData {
			likeMap := like.(map[string]interface{})
			postID := int(likeMap["post_id"].(float64))
			likesCount := 0
			if likeMap["likes_count"] != nil {
				likesCount = int(likeMap["likes_count"].(float64))
			}
			likesMap[postID] = likesCount
		}
	} else {
		likesMap = make(map[int]int)
	}

	// Process posts and combine likes count
	var posts []models.Post
	for _, postData := range postsData {
		postMap, ok := postData.(map[string]interface{})
		if !ok {
			log.Printf("postData is not a map: %v\n", postData)
			continue
		}

		postID := int(postMap["id"].(float64))

		createdAtStr, ok := postMap["created_at"].(string)
		var formattedCreatedAt string
		if ok {
			createdAt, err := time.Parse("2006-01-02T15:04:05", createdAtStr)
			if err != nil {
				log.Printf("Error parsing post created_at time: %v", err)
			} else {
				formattedCreatedAt = helpers.FormatTime(createdAt)
			}
		}

		posts = append(posts, models.Post{
			ID:                 uint(postID),
			Title:              postMap["title"].(string),
			Content:            postMap["content"].(string),
			FormattedCreatedAt: formattedCreatedAt,
			CommentsCount:      int(postMap["comments_aggregate"].(map[string]interface{})["aggregate"].(map[string]interface{})["count"].(float64)),
			LikesCount:         likesMap[postID], // Get likes count from the map
		})
	}

	blog := models.Blog{
		ID:          uint(blogData["id"].(float64)),
		Name:        blogData["name"].(string),
		Description: blogData["description"].(string),
		User: &models.User{
			ID:       userMap["id"].(string),
			Username: userMap["username"].(string),
		},
	}

	// Check if user is authenticated to determine if they can create posts
	session, ok := r.Context().Value("session").(*sessions.Session)
	isOwner := false
	if ok {
		tokenStr, ok := session.Values["token"].(string)
		if ok {
			claims := &auth.Claims{}
			token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
				return auth.JwtKey, nil
			})
			if err == nil && token.Valid {
				isOwner = claims.UserID == blog.User.ID
			}
		}
	}

	loggedIn := helpers.IsLoggedIn(r)

	log.Println("Rendering blog page")
	component := views.BlogPage(blog, posts, isOwner, loggedIn, "")
	templ.Handler(component).ServeHTTP(w, r)
	log.Println("Blog page rendered successfully")
}

func EditBlogFormHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	blogID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid blog ID", http.StatusBadRequest)
		return
	}

	session, _ := store.Get(r, "session-name")
	userID, ok := session.Values["userID"].(string)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	query := `
        query GetBlog($id: Int!) {
            blogs_by_pk(id: $id) {
                id
                name
                description
                image_path
                user {
                    id
                }
            }
        }
    `
	variables := map[string]interface{}{
		"id": blogID,
	}

	result, err := database.ExecuteGraphQL(query, variables)
	if err != nil {
		log.Printf("Failed to execute GraphQL query: %v", err)
		http.Error(w, "Failed to fetch blog", http.StatusInternalServerError)
		return
	}

	blogData, ok := result["blogs_by_pk"].(map[string]interface{})
	if !ok || blogData == nil {
		log.Printf("blogs_by_pk is nil or not a map: %v", result)
		http.Error(w, "Blog not found", http.StatusNotFound)
		return
	}

	blogOwnerID, ok := blogData["user"].(map[string]interface{})["id"].(string)
	if !ok || blogOwnerID != userID {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Check if image_path is nil and handle accordingly
	var imagePath string
	if blogData["image_path"] != nil {
		imagePath, ok = blogData["image_path"].(string)
		if !ok {
			imagePath = "" // Assign a default value or handle the error as needed
		}
	}

	blog := models.Blog{
		ID:          uint(blogData["id"].(float64)),
		Name:        blogData["name"].(string),
		Description: blogData["description"].(string),
		ImagePath:   imagePath,
	}

	component := views.EditBlog(blog)
	templ.Handler(component).ServeHTTP(w, r)
}

func EditBlogHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	blogID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid blog ID", http.StatusBadRequest)
		return
	}

	session, _ := store.Get(r, "session-name")
	userID, ok := session.Values["userID"].(string)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Query to get the blog details
	query := `
        query GetBlog($id: Int!) {
            blogs_by_pk(id: $id) {
                user_id
            }
        }
    `
	variables := map[string]interface{}{
		"id": blogID,
	}

	result, err := database.ExecuteGraphQL(query, variables)
	if err != nil {
		log.Printf("Failed to execute GraphQL query: %v", err)
		http.Error(w, "Failed to fetch blog", http.StatusInternalServerError)
		return
	}

	blogData, ok := result["blogs_by_pk"].(map[string]interface{})
	if !ok || blogData == nil {
		log.Printf("blogs_by_pk is nil or not a map: %v", result)
		http.Error(w, "Blog not found", http.StatusNotFound)
		return
	}

	blogOwnerID, ok := blogData["user_id"].(string)
	if !ok || blogOwnerID != userID {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var blog struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		ImagePath   string `json:"image_path"`
	}

	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "multipart/form-data") {
		err := r.ParseMultipartForm(10 << 20) // 10 MB
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		blog.Name = r.FormValue("name")
		blog.Description = r.FormValue("description")
		blog.ImagePath = r.FormValue("image_path")

		file, handler, err := r.FormFile("blog_image")
		if err == nil {
			defer file.Close()
			// Generate a unique file name and upload to Google Cloud Storage
			fileName := fmt.Sprintf("%s%s", uuid.New().String(), filepath.Ext(handler.Filename))
			blog.ImagePath, err = helpers.UploadFileToCloudinary(file, fileName)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
	} else if strings.Contains(contentType, "application/json") {
		err := json.NewDecoder(r.Body).Decode(&blog)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		blog.Name = r.FormValue("name")
		blog.Description = r.FormValue("description")
		blog.ImagePath = r.FormValue("image_path")
	} else {
		http.Error(w, "Unsupported content type", http.StatusUnsupportedMediaType)
		return
	}

	query = `
        mutation UpdateBlog($id: Int!, $name: String!, $description: String!, $image_path: String!) {
            update_blogs(where: {id: {_eq: $id}}, _set: {name: $name, description: $description, image_path: $image_path}) {
                affected_rows
            }
        }
    `
	variables = map[string]interface{}{
		"id":          blogID,
		"name":        blog.Name,
		"description": blog.Description,
		"image_path":  blog.ImagePath,
	}

	result, err = database.ExecuteGraphQL(query, variables)
	if err != nil {
		log.Printf("Error executing GraphQL mutation: %v", err)
		http.Error(w, "Failed to update blog", http.StatusInternalServerError)
		return
	}

	log.Printf("GraphQL mutation result: %v", result)
	w.Header().Set("HX-Redirect", fmt.Sprintf("/blogs/%d", blogID))
	w.WriteHeader(http.StatusOK)
}

func DeleteBlogHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	blogID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid blog ID", http.StatusBadRequest)
		return
	}

	session, _ := store.Get(r, "session-name")
	userID, ok := session.Values["userID"].(string)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	log.Printf("Attempting to delete blog with ID %d for user ID %s", blogID, userID)

	// GraphQL mutation to delete the blog
	deleteBlogQuery := `
        mutation DeleteBlog($id: Int!, $user_id: uuid!) {
            delete_blogs(where: {id: {_eq: $id}, user_id: {_eq: $user_id}}) {
                affected_rows
            }
        }
    `
	blogVariables := map[string]interface{}{
		"id":      blogID,
		"user_id": userID,
	}

	result, err := database.ExecuteGraphQL(deleteBlogQuery, blogVariables)
	if err != nil {
		log.Printf("Error executing GraphQL mutation: %v", err)
		http.Error(w, "Failed to delete blog", http.StatusInternalServerError)
		return
	}

	log.Printf("GraphQL mutation result: %v", result)

	affectedRows, ok := result["delete_blogs"].(map[string]interface{})["affected_rows"].(float64) // Note: GraphQL typically returns floats for numerical values
	if !ok || int(affectedRows) == 0 {
		log.Printf("No rows affected. Blog not found or user not authorized.")
		http.Error(w, "Blog not found or you are not authorized to delete it", http.StatusBadRequest)
		return
	}

	// GraphQL mutation to delete the user
	deleteUserQuery := `
        mutation DeleteUser($id: uuid!) {
            delete_users(where: {id: {_eq: $id}}) {
                affected_rows
            }
        }
    `
	userVariables := map[string]interface{}{
		"id": userID,
	}

	_, err = database.ExecuteGraphQL(deleteUserQuery, userVariables)
	if err != nil {
		log.Printf("Error executing GraphQL mutation to delete user: %v", err)
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	// Clear the user's session and log them out
	session.Values["token"] = ""
	session.Values["userID"] = ""
	session.Options.MaxAge = -1 // This will delete the session

	err = session.Save(r, w)
	if err != nil {
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}

	cookie := &http.Cookie{
		Name:     "session-name",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)

	log.Printf("User and blog deletion successful, user logged out.")
	w.Header().Set("HX-Redirect", "/")
	w.WriteHeader(http.StatusOK)
}
