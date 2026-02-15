package handlers

import (
	"blogflex/internal/database"
	"blogflex/internal/helpers"
	"blogflex/internal/models"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

func GetCommentsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	postID, err := strconv.Atoi(vars["postID"])
	if err != nil {
		http.Error(w, "Invalid post ID", http.StatusBadRequest)
		return
	}

	query := `
        query GetComments($post_id: Int!) {
            comments(where: {post_id: {_eq: $post_id}}) {
                id
                content
                post_id
                user_id
            }
        }
    `
	variables := map[string]interface{}{
		"post_id": postID,
	}

	result, err := helpers.GraphQLRequest(query, variables)
	if err != nil || len(result["errors"].([]interface{})) > 0 {
		http.Error(w, "Failed to fetch comments", http.StatusInternalServerError)
		return
	}

	commentsData := result["data"].(map[string]interface{})["comments"].([]interface{})
	var comments []models.Comment
	for _, commentData := range commentsData {
		commentMap := commentData.(map[string]interface{})
		comments = append(comments, models.Comment{
			ID:      uint(commentMap["id"].(float64)),
			Content: commentMap["content"].(string),
			PostID:  uint(commentMap["post_id"].(float64)),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(comments)
}

func ToggleLikePostHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	postID, err := strconv.Atoi(vars["id"])
	if err != nil {
		helpers.RespondWithError(w, http.StatusBadRequest, "Invalid post ID")
		return
	}

	session, _ := store.Get(r, "session-name")
	userID, ok := session.Values["userID"].(string)
	if !ok {
		helpers.RespondWithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Check if the user is the post owner (users can't like their own posts)
	postOwnerQuery := `
        query GetPostOwner($id: Int!) {
            posts_by_pk(id: $id) {
                user_id
            }
        }
    `
	postOwnerVariables := map[string]interface{}{
		"id": postID,
	}

	postOwnerResult, err := database.ExecuteGraphQL(postOwnerQuery, postOwnerVariables)
	if err != nil {
		log.Printf("Failed to fetch post owner: %v", err)
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch post details")
		return
	}

	postData, ok := postOwnerResult["posts_by_pk"].(map[string]interface{})
	if !ok || postData == nil {
		log.Printf("posts_by_pk is nil or not a map: %v", postOwnerResult)
		helpers.RespondWithError(w, http.StatusNotFound, "Post not found")
		return
	}

	postOwnerID, ok := postData["user_id"].(string)
	if !ok {
		log.Printf("user_id is not a string: %v", postData["user_id"])
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch post owner")
		return
	}

	// If the user is the post owner, they can't like their own post
	if userID == postOwnerID {
		helpers.RespondWithError(w, http.StatusForbidden, "You cannot like your own post")
		return
	}

	// Check if the user has already liked the post
	query := `
        query CheckLike($post_id: Int!, $user_id: uuid!) {
            likes(where: {post_id: {_eq: $post_id}, user_id: {_eq: $user_id}}) {
                id
            }
        }
    `
	variables := map[string]interface{}{
		"post_id": postID,
		"user_id": userID,
	}

	result, err := database.ExecuteGraphQL(query, variables)
	if err != nil {
		log.Printf("Failed to check like status: %v", err)
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to retrieve like status")
		return
	}

	log.Printf("CheckLike result: %v", result)

	likes, ok := result["likes"].([]interface{})
	if !ok {
		log.Printf("Unexpected format for 'likes': %v", result)
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to retrieve like status")
		return
	}

	if len(likes) > 0 {
		// User has liked the post, so unlike it
		likeID := likes[0].(map[string]interface{})["id"].(float64)
		deleteQuery := `
            mutation UnlikePost($id: Int!) {
                delete_likes_by_pk(id: $id) {
                    id
                }
            }
        `
		deleteVariables := map[string]interface{}{
			"id": int(likeID),
		}

		_, err = database.ExecuteGraphQL(deleteQuery, deleteVariables)
		if err != nil {
			log.Printf("Failed to unlike post: %v", err)
			helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to unlike post")
			return
		}
	} else {
		// User has not liked the post, so like it
		likeQuery := `
            mutation LikePost($post_id: Int!, $user_id: uuid!, $created_at: timestamptz!) {
                insert_likes_one(object: {post_id: $post_id, user_id: $user_id, created_at: $created_at}) {
                    id
                }
            }
        `
		likeVariables := map[string]interface{}{
			"post_id":    postID,
			"user_id":    userID,
			"created_at": time.Now().Format(time.RFC3339),
		}

		_, err = database.ExecuteGraphQL(likeQuery, likeVariables)
		if err != nil {
			log.Printf("Failed to like post: %v", err)
			helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to like post")
			return
		}
	}

	// Fetch updated like count
	likesCountQuery := `
        query GetLikesCount($post_id: Int!) {
            posts_with_likes(where: {post_id: {_eq: $post_id}}) {
                likes_count
            }
        }
    `
	likesCountVariables := map[string]interface{}{
		"post_id": postID,
	}

	likesCountResult, err := database.ExecuteGraphQL(likesCountQuery, likesCountVariables)
	if err != nil {
		log.Printf("Failed to fetch likes count: %v", err)
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch likes count")
		return
	}

	log.Printf("GetLikesCount result: %v", likesCountResult)

	postsWithLikes, ok := likesCountResult["posts_with_likes"].([]interface{})
	if !ok || len(postsWithLikes) == 0 {
		log.Printf("Unexpected format or empty 'posts_with_likes': %v", likesCountResult)
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch likes count")
		return
	}

	likesCount := int(postsWithLikes[0].(map[string]interface{})["likes_count"].(float64))

	// Determine if the user has liked the post after this action
	// We need to check if the user has liked the post after this action
	// If we had likes before and deleted one, the user has unliked the post
	// If we had no likes before and added one, the user has liked the post
	hasLiked := false
	if len(likes) > 0 {
		// We had likes before, so we just unliked the post
		hasLiked = false
	} else {
		// We had no likes before, so we just liked the post
		hasLiked = true
	}
	buttonClass := "btn-primary"
	statusText := "You liked this post"

	if !hasLiked {
		buttonClass = "btn-outline-primary"
		statusText = "Like this post"
	}

	// Return the updated HTML for the button
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`<button id="like-button" hx-post="/protected/posts/%d/like" hx-target="#like-button" hx-swap="outerHTML" class="%s">
        <i class="fas fa-thumbs-up"></i> <span id="likes-count">%d</span>
    </button>
    <small class="text-muted ml-2">%s</small>`, postID, buttonClass, likesCount, statusText)))
}

func AddCommentHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	postID, err := strconv.Atoi(vars["id"])
	if err != nil {
		helpers.RespondWithError(w, http.StatusBadRequest, "Invalid post ID")
		return
	}

	session, _ := store.Get(r, "session-name")
	userID, ok := session.Values["userID"].(string)
	if !ok {
		helpers.RespondWithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var input struct {
		Content string `json:"content"`
	}

	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			log.Printf("Error decoding JSON input: %v", err)
			http.Error(w, "Invalid input", http.StatusBadRequest)
			return
		}
	} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err != nil {
			log.Printf("Error parsing form input: %v", err)
			http.Error(w, "Invalid input", http.StatusBadRequest)
			return
		}
		input.Content = r.FormValue("content")
	} else {
		log.Printf("Unsupported content type: %v", contentType)
		http.Error(w, "Unsupported content type", http.StatusUnsupportedMediaType)
		return
	}

	comment := models.Comment{
		PostID:    uint(postID),
		UserID:    userID,
		Content:   input.Content,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	query := `
        mutation AddComment($content: String!, $post_id: Int!, $user_id: uuid!, $created_at: timestamp!, $updated_at: timestamp!) {
            insert_comments_one(object: {content: $content, post_id: $post_id, user_id: $user_id, created_at: $created_at, updated_at: $updated_at}) {
                id
                content
                user {
                    id
                    username
                }
                created_at
                updated_at
                user_id
            }
        }
    `
	variables := map[string]interface{}{
		"content":    comment.Content,
		"post_id":    comment.PostID,
		"user_id":    comment.UserID,
		"created_at": comment.CreatedAt.Format(time.RFC3339),
		"updated_at": comment.UpdatedAt.Format(time.RFC3339),
	}

	result, err := database.ExecuteGraphQL(query, variables)
	if err != nil {
		log.Printf("Error executing GraphQL request: %v", err)
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to add comment")
		return
	}

	newCommentData, ok := result["insert_comments_one"].(map[string]interface{})
	if !ok {
		log.Printf("Unexpected format for insert_comments_one: %v", result)
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to add comment")
		return
	}

	comment.ID = uint(newCommentData["id"].(float64))

	// Parse timestamps
	if createdAtStr, ok := newCommentData["created_at"].(string); ok {
		parsedTime, err := time.Parse(time.RFC3339, createdAtStr)
		if err == nil {
			comment.CreatedAt = parsedTime
		} else {
			// If parsing fails, use current time
			comment.CreatedAt = time.Now()
			log.Printf("Error parsing created_at time: %v", err)
		}
	} else {
		// If created_at is missing, use current time
		comment.CreatedAt = time.Now()
	}

	if updatedAtStr, ok := newCommentData["updated_at"].(string); ok {
		parsedTime, err := time.Parse(time.RFC3339, updatedAtStr)
		if err == nil {
			comment.UpdatedAt = parsedTime
		} else {
			// If parsing fails, use current time
			comment.UpdatedAt = time.Now()
			log.Printf("Error parsing updated_at time: %v", err)
		}
	} else {
		// If updated_at is missing, use current time
		comment.UpdatedAt = time.Now()
	}

	// Get the user data from the database
	userQuery := `
		query GetUser($user_id: uuid!) {
			users(where: {id: {_eq: $user_id}}) {
				id
				username
			}
		}
	`
	userVariables := map[string]interface{}{
		"user_id": userID,
	}

	userResult, err := database.ExecuteGraphQL(userQuery, userVariables)
	if err != nil {
		log.Printf("Error fetching user data: %v", err)
		// Continue with default user data
	}

	// Set default user data
	username := "Unknown User"

	// Try to get user data from the comment result first
	if userData, ok := newCommentData["user"].(map[string]interface{}); ok && userData != nil {
		if usernameStr, ok := userData["username"].(string); ok && usernameStr != "" {
			username = usernameStr
		}
	} else if userResult != nil {
		// If not available in comment, try from the user query
		if users, ok := userResult["users"].([]interface{}); ok && len(users) > 0 {
			if user, ok := users[0].(map[string]interface{}); ok {
				if usernameStr, ok := user["username"].(string); ok && usernameStr != "" {
					username = usernameStr
				}
			}
		}
	}

	comment.User = &models.User{
		ID:       userID,
		Username: username,
	}

comment.UserID = userID
formattedCreatedAt := helpers.FormatTime(comment.CreatedAt)

// Render the new comment as HTML
	commentHTML := fmt.Sprintf(`
        <div class="list-group-item list-group-item-action mt-2 pt-2" id="comment-%d">
            <div class="d-flex justify-content-between">
                <p class="text-gray-700 mb-1"><strong>%s</strong> posted on %s</p>
                <div>
                    <button class="btn btn-sm btn-outline-danger delete-comment-btn"
                        hx-delete="/protected/comments/%d"
                        hx-confirm="Are you sure you want to delete this comment?"
                        hx-target="#comment-%d"
                        hx-swap="outerHTML">
                        <i class="fas fa-trash"></i> Delete
                    </button>
                </div>
            </div>
            <p class="text-gray-700 comment-content">%s</p>
        </div>`,
		comment.ID, comment.User.Username, formattedCreatedAt, comment.ID, comment.ID, comment.Content)

	// Set appropriate headers for HTMX
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("HX-Trigger", "resetCommentForm")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(commentHTML))
}

func GetLikesCountHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	postID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid post ID", http.StatusBadRequest)
		return
	}

	query := `
        query GetLikesCount($post_id: Int!) {
            likes_count(where: {post_id: {_eq: $post_id}}) {
                aggregate {
                    count
                }
            }
        }
    `
	variables := map[string]interface{}{
		"post_id": postID,
	}

	result, err := helpers.GraphQLRequest(query, variables)
	if err != nil || len(result["errors"].([]interface{})) > 0 {
		http.Error(w, "Failed to fetch likes count", http.StatusInternalServerError)
		return
	}

	count := result["data"].(map[string]interface{})["likes_count"].(map[string]interface{})["aggregate"].(map[string]interface{})["count"].(float64)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"count": int(count)})
}

// EditCommentHandler handles updating a comment
func EditCommentHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	commentID, err := strconv.Atoi(vars["id"])
	if err != nil {
		helpers.RespondWithError(w, http.StatusBadRequest, "Invalid comment ID")
		return
	}

	// Get the current user ID from the session
	session, _ := store.Get(r, "session-name")
	userID, ok := session.Values["userID"].(string)
	if !ok {
		helpers.RespondWithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// First, check if the comment belongs to the user OR if the user is the post owner
	checkQuery := `
		query CheckCommentPermission($id: Int!) {
			comments(where: {id: {_eq: $id}}) {
				id
				user_id
				post {
					id
					user_id
				}
			}
		}
	`
	checkVariables := map[string]interface{}{
		"id": commentID,
	}

	checkResult, err := database.ExecuteGraphQL(checkQuery, checkVariables)
	if err != nil {
		log.Printf("Error checking comment permission: %v", err)
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to verify comment permission")
		return
	}

	comments, ok := checkResult["comments"].([]interface{})
	if !ok || len(comments) == 0 {
		helpers.RespondWithError(w, http.StatusNotFound, "Comment not found")
		return
	}

	// Check if user is either the comment owner or the post owner
	commentData := comments[0].(map[string]interface{})
	commentUserID, ok := commentData["user_id"].(string)
	if !ok {
		log.Printf("Error getting comment user ID: %v", commentData)
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to verify comment permission")
		return
	}

	var postData map[string]interface{}
	var postUserID string

	if postInfo, ok := commentData["post"].(map[string]interface{}); ok && postInfo != nil {
		postData = postInfo
		if postIDStr, ok := postData["user_id"].(string); ok && postIDStr != "" {
			postUserID = postIDStr
		} else {
			log.Printf("Error getting post user ID: %v", postData)
			// Continue with empty post user ID
			postUserID = ""
		}
	} else {
		log.Printf("Error getting post data: %v", commentData)
		// Continue with empty post user ID
		postUserID = ""
	}

	// If postUserID is empty, only allow the comment owner to edit
	if postUserID == "" {
		if userID != commentUserID {
			helpers.RespondWithError(w, http.StatusForbidden, "You can only edit your own comments")
			return
		}
	} else {
		// Otherwise, allow both the comment owner and post owner to edit
		if userID != commentUserID && userID != postUserID {
			helpers.RespondWithError(w, http.StatusForbidden, "You can only edit your own comments or comments on your posts")
			return
		}
	}

	// Parse the request body to get the updated content
	var input struct {
		Content string `json:"content"`
	}

	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			log.Printf("Error decoding JSON input: %v", err)
			http.Error(w, "Invalid input", http.StatusBadRequest)
			return
		}
	} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err != nil {
			log.Printf("Error parsing form input: %v", err)
			http.Error(w, "Invalid input", http.StatusBadRequest)
			return
		}
		input.Content = r.FormValue("edit-comment-text-" + vars["id"])
		if input.Content == "" {
			input.Content = r.FormValue("content")
		}
	} else {
		log.Printf("Unsupported content type: %v", contentType)
		http.Error(w, "Unsupported content type", http.StatusUnsupportedMediaType)
		return
	}

	// Update the comment
	updateQuery := `
		mutation UpdateComment($id: Int!, $content: String!, $updated_at: timestamp!) {
			update_comments(where: {id: {_eq: $id}}, _set: {content: $content, updated_at: $updated_at}) {
				affected_rows
				returning {
					id
					content
					user {
						id
						username
					}
					created_at
					updated_at
					user_id
				}
			}
		}
	`
	updateVariables := map[string]interface{}{
		"id":         commentID,
		"content":    input.Content,
		"updated_at": time.Now().Format(time.RFC3339),
	}

	updateResult, err := database.ExecuteGraphQL(updateQuery, updateVariables)
	if err != nil {
		log.Printf("Error updating comment: %v", err)
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to update comment")
		return
	}

	// Get the updated comment
	updateData, ok := updateResult["update_comments"].(map[string]interface{})
	if !ok {
		log.Printf("Unexpected format for update_comments: %v", updateResult)
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to update comment")
		return
	}

	returning, ok := updateData["returning"].([]interface{})
	if !ok || len(returning) == 0 {
		log.Printf("No comment returned after update: %v", updateData)
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to update comment")
		return
	}

	updatedCommentData := returning[0].(map[string]interface{})
comment := models.Comment{
ID:      uint(updatedCommentData["id"].(float64)),
Content: updatedCommentData["content"].(string),
User: &models.User{
ID:       updatedCommentData["user"].(map[string]interface{})["id"].(string),
Username: updatedCommentData["user"].(map[string]interface{})["username"].(string),
},
CreatedAt: time.Now(), // Default value
}

	// Parse the created_at timestamp
	if createdAtStr, ok := updatedCommentData["created_at"].(string); ok {
		if createdAt, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
			comment.CreatedAt = createdAt
		}
	}

formattedCreatedAt := helpers.FormatTime(comment.CreatedAt)

	// Render the updated comment HTML
	commentHTML := fmt.Sprintf(`
		<div class="list-group-item list-group-item-action mt-2 pt-2" id="comment-%d">
			<div class="d-flex justify-content-between">
				<p class="text-gray-700 mb-1"><strong>%s</strong> posted on %s</p>
				<div>
					<button class="btn btn-sm btn-outline-warning mr-1 edit-comment-btn" 
						onclick="editComment(%d)">
						<i class="fas fa-edit"></i>
					</button>
					<button class="btn btn-sm btn-outline-danger delete-comment-btn"
						hx-delete="/protected/comments/%d"
						hx-confirm="Are you sure you want to delete this comment?"
						hx-target="#comment-%d"
						hx-swap="outerHTML">
						<i class="fas fa-trash"></i>
					</button>
				</div>
			</div>
			<p class="text-gray-700 comment-content" id="comment-content-%d">%s</p>
			<div class="edit-comment-form d-none" id="edit-form-%d">
				<textarea class="form-control mb-2" id="edit-comment-text-%d">%s</textarea>
				<button class="btn btn-sm btn-primary mr-1" 
					hx-put="/protected/comments/%d"
					hx-include="#edit-comment-text-%d"
					hx-target="#comment-%d"
					hx-swap="outerHTML">
					Save
				</button>
				<button class="btn btn-sm btn-secondary" onclick="cancelEdit(%d)">Cancel</button>
			</div>
</div>`,
comment.ID, comment.User.Username, formattedCreatedAt,
comment.ID, comment.ID, comment.ID, comment.ID, comment.Content, comment.ID, comment.ID, comment.Content, comment.ID, comment.ID, comment.ID, comment.ID)

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(commentHTML))
}

// DeleteCommentHandler handles deleting a comment
func DeleteCommentHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	commentID, err := strconv.Atoi(vars["id"])
	if err != nil {
		helpers.RespondWithError(w, http.StatusBadRequest, "Invalid comment ID")
		return
	}

	// Get the current user ID from the session
	session, _ := store.Get(r, "session-name")
	userID, ok := session.Values["userID"].(string)
	if !ok {
		helpers.RespondWithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// First, check if the comment belongs to the user OR if the user is the post owner
	checkQuery := `
		query CheckCommentPermission($id: Int!) {
			comments(where: {id: {_eq: $id}}) {
				id
				user_id
				post {
					id
					user_id
				}
			}
		}
	`
	checkVariables := map[string]interface{}{
		"id": commentID,
	}

	checkResult, err := database.ExecuteGraphQL(checkQuery, checkVariables)
	if err != nil {
		log.Printf("Error checking comment permission: %v", err)
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to verify comment permission")
		return
	}

	comments, ok := checkResult["comments"].([]interface{})
	if !ok || len(comments) == 0 {
		helpers.RespondWithError(w, http.StatusNotFound, "Comment not found")
		return
	}

	// Check if user is either the comment owner or the post owner
	commentData := comments[0].(map[string]interface{})
	commentUserID, ok := commentData["user_id"].(string)
	if !ok {
		log.Printf("Error getting comment user ID: %v", commentData)
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to verify comment permission")
		return
	}

	var postData map[string]interface{}
	var postUserID string

	if postInfo, ok := commentData["post"].(map[string]interface{}); ok && postInfo != nil {
		postData = postInfo
		if postIDStr, ok := postData["user_id"].(string); ok && postIDStr != "" {
			postUserID = postIDStr
		} else {
			log.Printf("Error getting post user ID: %v", postData)
			// Continue with empty post user ID
			postUserID = ""
		}
	} else {
		log.Printf("Error getting post data: %v", commentData)
		// Continue with empty post user ID
		postUserID = ""
	}

	// If postUserID is empty, only allow the comment owner to delete
	if postUserID == "" {
		if userID != commentUserID {
			helpers.RespondWithError(w, http.StatusForbidden, "You can only delete your own comments")
			return
		}
	} else {
		// Otherwise, allow both the comment owner and post owner to delete
		if userID != commentUserID && userID != postUserID {
			helpers.RespondWithError(w, http.StatusForbidden, "You can only delete your own comments or comments on your posts")
			return
		}
	}

	// Delete the comment
	deleteQuery := `
		mutation DeleteComment($id: Int!) {
			delete_comments(where: {id: {_eq: $id}}) {
				affected_rows
			}
		}
	`
	deleteVariables := map[string]interface{}{
		"id": commentID,
	}

	deleteResult, err := database.ExecuteGraphQL(deleteQuery, deleteVariables)
	if err != nil {
		log.Printf("Error deleting comment: %v", err)
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to delete comment")
		return
	}

	// Check if the comment was deleted
	deleteData, ok := deleteResult["delete_comments"].(map[string]interface{})
	if !ok {
		log.Printf("Unexpected format for delete_comments: %v", deleteResult)
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to delete comment")
		return
	}

	affectedRows, ok := deleteData["affected_rows"].(float64)
	if !ok || affectedRows == 0 {
		log.Printf("No comment deleted: %v", deleteData)
		helpers.RespondWithError(w, http.StatusInternalServerError, "Failed to delete comment")
		return
	}

	// Return an empty response with 200 OK status
	w.WriteHeader(http.StatusOK)
}
