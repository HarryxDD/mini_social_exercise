from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import collections
import json
import sqlite3
import hashlib
import re
from datetime import datetime
import math
from nltk.corpus import stopwords
import nltk

app = Flask(__name__)
app.secret_key = '123456789' 
DATABASE = 'database.sqlite'

# Load censorship data
# WARNING! The censorship.dat file contains disturbing language when decrypted. 
# If you want to test whether moderation works, 
# you can trigger censorship using these words: 
# tier1badword, tier2badword, tier3badword
ENCRYPTED_FILE_PATH = 'censorship.dat'
fernet = Fernet('xpplx11wZUibz0E8tV8Z9mf-wwggzSrc21uQ17Qq2gg=')
with open(ENCRYPTED_FILE_PATH, 'rb') as encrypted_file:
    encrypted_data = encrypted_file.read()
decrypted_data = fernet.decrypt(encrypted_data)
MODERATION_CONFIG = json.loads(decrypted_data)
TIER1_WORDS = MODERATION_CONFIG['categories']['tier1_severe_violations']['words']
TIER2_PHRASES = MODERATION_CONFIG['categories']['tier2_spam_scams']['phrases']
TIER3_WORDS = MODERATION_CONFIG['categories']['tier3_mild_profanity']['words']

try:
    STOP_WORDS = set(stopwords.words('english'))
except LookupError:
    # Download stopwords data if not already present
    nltk.download('stopwords', quiet=True)
    STOP_WORDS = set(stopwords.words('english'))

def get_db():
    """
    Connect to the application's configured database. The connection
    is unique for each request and will be reused if this is called
    again.
    """
    if 'db' not in g:
        g.db = sqlite3.connect(
            DATABASE,
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row

    return g.db


@app.teardown_appcontext
def close_connection(exception):
    """Closes the database again at the end of the request."""
    db = g.pop('db', None)

    if db is not None:
        db.close()


def query_db(query, args=(), one=False, commit=False):
    """
    Queries the database and returns a list of dictionaries, a single
    dictionary, or None. Also handles write operations.
    """
    db = get_db()
    
    # Using 'with' on a connection object implicitly handles transactions.
    # The 'with' statement will automatically commit if successful, 
    # or rollback if an exception occurs. This is safer.
    try:
        with db:
            cur = db.execute(query, args)
        
        # For SELECT statements, fetch the results after the transaction block
        if not commit:
            rv = cur.fetchall()
            return (rv[0] if rv else None) if one else rv
        
        # For write operations, we might want the cursor to get info like lastrowid
        return cur

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None

@app.template_filter('datetimeformat')
def datetimeformat(value):
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        dt = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
    else:
        return "N/A"
    return dt.strftime('%b %d, %Y %H:%M')

REACTION_EMOJIS = {
    'like': '❤️', 'love': '😍', 'laugh': '😂',
    'wow': '😮', 'sad': '😢', 'angry': '😠',
}
REACTION_TYPES = list(REACTION_EMOJIS.keys())


@app.route('/')
def feed():
    #  1. Get Pagination and Filter Parameters 
    try:
        page = int(request.args.get('page', 1))
    except ValueError:
        page = 1
    sort = request.args.get('sort', 'new').lower()
    show = request.args.get('show', 'all').lower()
    
    # Define how many posts to show per page
    POSTS_PER_PAGE = 10
    offset = (page - 1) * POSTS_PER_PAGE

    current_user_id = session.get('user_id')
    params = []

    #  2. Build the Query 
    where_clause = ""
    if show == 'following' and current_user_id:
        where_clause = "WHERE p.user_id IN (SELECT followed_id FROM follows WHERE follower_id = ?)"
        params.append(current_user_id)

    # Add the pagination parameters to the query arguments
    pagination_params = (POSTS_PER_PAGE, offset)

    if sort == 'popular':
        query = f"""
            SELECT p.id, p.content, p.created_at, u.username, u.id as user_id,
                   IFNULL(r.total_reactions, 0) as total_reactions
            FROM posts p
            JOIN users u ON p.user_id = u.id
            LEFT JOIN (
                SELECT post_id, COUNT(*) as total_reactions FROM reactions GROUP BY post_id
            ) r ON p.id = r.post_id
            {where_clause}
            ORDER BY total_reactions DESC, p.created_at DESC
            LIMIT ? OFFSET ?
        """
        final_params = params + list(pagination_params)
        posts = query_db(query, final_params)
    elif sort == 'recommended':
        posts = recommend(current_user_id, show == 'following' and current_user_id)
    else:  # Default sort is 'new'
        query = f"""
            SELECT p.id, p.content, p.created_at, u.username, u.id as user_id
            FROM posts p
            JOIN users u ON p.user_id = u.id
            {where_clause}
            ORDER BY p.created_at DESC
            LIMIT ? OFFSET ?
        """
        final_params = params + list(pagination_params)
        posts = query_db(query, final_params)

    posts_data = []
    for post in posts:
        # Determine if the current user follows the poster
        followed_poster = False
        if current_user_id and post['user_id'] != current_user_id:
            follow_check = query_db(
                'SELECT 1 FROM follows WHERE follower_id = ? AND followed_id = ?',
                (current_user_id, post['user_id']),
                one=True
            )
            if follow_check:
                followed_poster = True

        # Determine if the current user reacted to this post and with what reaction
        user_reaction = None
        if current_user_id:
            reaction_check = query_db(
                'SELECT reaction_type FROM reactions WHERE user_id = ? AND post_id = ?',
                (current_user_id, post['id']),
                one=True
            )
            if reaction_check:
                user_reaction = reaction_check['reaction_type']

        reactions = query_db('SELECT reaction_type, COUNT(*) as count FROM reactions WHERE post_id = ? GROUP BY reaction_type', (post['id'],))
        comments_raw = query_db('SELECT c.id, c.content, c.created_at, u.username, u.id as user_id FROM comments c JOIN users u ON c.user_id = u.id WHERE c.post_id = ? ORDER BY c.created_at ASC', (post['id'],))
        post_dict = dict(post)
        post_dict['content'], _ = moderate_content(post_dict['content'])
        comments_moderated = []
        for comment in comments_raw:
            comment_dict = dict(comment)
            comment_dict['content'], _ = moderate_content(comment_dict['content'])
            comments_moderated.append(comment_dict)
        posts_data.append({
            'post': post_dict,
            'reactions': reactions,
            'user_reaction': user_reaction,
            'followed_poster': followed_poster,
            'comments': comments_moderated
        })

    #  4. Render Template with Pagination Info 
    return render_template('feed.html.j2', 
                           posts=posts_data, 
                           current_sort=sort,
                           current_show=show,
                           page=page, # Pass current page number
                           per_page=POSTS_PER_PAGE, # Pass items per page
                           reaction_emojis=REACTION_EMOJIS,
                           reaction_types=REACTION_TYPES)

@app.route('/posts/new', methods=['POST'])
def add_post():
    """Handles creating a new post from the feed."""
    user_id = session.get('user_id')

    # Block access if user is not logged in
    if not user_id:
        flash('You must be logged in to create a post.', 'danger')
        return redirect(url_for('login'))

    # Get content from the submitted form
    content = request.form.get('content')

    # Pass the user's content through the moderation function
    moderated_content = content

    # Basic validation to ensure post is not empty
    if moderated_content and moderated_content.strip():
        db = get_db()
        db.execute('INSERT INTO posts (user_id, content) VALUES (?, ?)',
                   (user_id, moderated_content))
        db.commit()
        flash('Your post was successfully created!', 'success')
    else:
        # This will catch empty posts or posts that were fully censored
        flash('Post cannot be empty or was fully censored.', 'warning')

    # Redirect back to the main feed to see the new post
    return redirect(url_for('feed'))
    
    
@app.route('/posts/<int:post_id>/delete', methods=['POST'])
def delete_post(post_id):
    """Handles deleting a post."""
    user_id = session.get('user_id')

    # Block access if user is not logged in
    if not user_id:
        flash('You must be logged in to delete a post.', 'danger')
        return redirect(url_for('login'))

    # Find the post in the database
    post = query_db('SELECT id, user_id FROM posts WHERE id = ?', (post_id,), one=True)

    # Check if the post exists and if the current user is the owner
    if not post:
        flash('Post not found.', 'danger')
        return redirect(url_for('feed'))

    if post['user_id'] != user_id:
        # Security check: prevent users from deleting others' posts
        flash('You do not have permission to delete this post.', 'danger')
        return redirect(url_for('feed'))

    # If all checks pass, proceed with deletion
    db = get_db()
    # To maintain database integrity, delete associated records first
    db.execute('DELETE FROM comments WHERE post_id = ?', (post_id,))
    db.execute('DELETE FROM reactions WHERE post_id = ?', (post_id,))
    # Finally, delete the post itself
    db.execute('DELETE FROM posts WHERE id = ?', (post_id,))
    db.commit()

    flash('Your post was successfully deleted.', 'success')
    # Redirect back to the page the user came from, or the feed as a fallback
    return redirect(request.referrer or url_for('feed'))

@app.route('/u/<username>')
def user_profile(username):
    """Displays a user's profile page with moderated bio, posts, and latest comments."""
    
    user_raw = query_db('SELECT * FROM users WHERE username = ?', (username,), one=True)
    if not user_raw:
        abort(404)

    user = dict(user_raw)
    moderated_bio, _ = moderate_content(user.get('profile', ''))
    user['profile'] = moderated_bio

    posts_raw = query_db('SELECT id, content, user_id, created_at FROM posts WHERE user_id = ? ORDER BY created_at DESC', (user['id'],))
    posts = []
    for post_raw in posts_raw:
        post = dict(post_raw)
        moderated_post_content, _ = moderate_content(post['content'])
        post['content'] = moderated_post_content
        posts.append(post)

    comments_raw = query_db('SELECT id, content, user_id, post_id, created_at FROM comments WHERE user_id = ? ORDER BY created_at DESC LIMIT 100', (user['id'],))
    comments = []
    for comment_raw in comments_raw:
        comment = dict(comment_raw)
        moderated_comment_content, _ = moderate_content(comment['content'])
        comment['content'] = moderated_comment_content
        comments.append(comment)

    followers_count = query_db('SELECT COUNT(*) as cnt FROM follows WHERE followed_id = ?', (user['id'],), one=True)['cnt']
    following_count = query_db('SELECT COUNT(*) as cnt FROM follows WHERE follower_id = ?', (user['id'],), one=True)['cnt']

    #  NEW: CHECK FOLLOW STATUS 
    is_currently_following = False # Default to False
    current_user_id = session.get('user_id')
    
    # We only need to check if a user is logged in
    if current_user_id:
        follow_relation = query_db(
            'SELECT 1 FROM follows WHERE follower_id = ? AND followed_id = ?',
            (current_user_id, user['id']),
            one=True
        )
        if follow_relation:
            is_currently_following = True
    # --

    return render_template('user_profile.html.j2', 
                           user=user, 
                           posts=posts, 
                           comments=comments,
                           followers_count=followers_count, 
                           following_count=following_count,
                           is_following=is_currently_following)
    

@app.route('/u/<username>/followers')
def user_followers(username):
    user = query_db('SELECT * FROM users WHERE username = ?', (username,), one=True)
    if not user:
        abort(404)
    followers = query_db('''
        SELECT u.username
        FROM follows f
        JOIN users u ON f.follower_id = u.id
        WHERE f.followed_id = ?
    ''', (user['id'],))
    return render_template('user_list.html.j2', user=user, users=followers, title="Followers of")

@app.route('/u/<username>/following')
def user_following(username):
    user = query_db('SELECT * FROM users WHERE username = ?', (username,), one=True)
    if not user:
        abort(404)
    following = query_db('''
        SELECT u.username
        FROM follows f
        JOIN users u ON f.followed_id = u.id
        WHERE f.follower_id = ?
    ''', (user['id'],))
    return render_template('user_list.html.j2', user=user, users=following, title="Users followed by")

@app.route('/posts/<int:post_id>')
def post_detail(post_id):
    """Displays a single post and its comments, with content moderation applied."""
    
    post_raw = query_db('''
        SELECT p.id, p.content, p.created_at, u.username, u.id as user_id
        FROM posts p
        JOIN users u ON p.user_id = u.id
        WHERE p.id = ?
    ''', (post_id,), one=True)

    if not post_raw:
        # The abort function will stop the request and show a 404 Not Found page.
        abort(404)

    #  Moderation for the Main Post 
    # Convert the raw database row to a mutable dictionary
    post = dict(post_raw)
    # Unpack the tuple from moderate_content, we only need the moderated content string here
    moderated_post_content, _ = moderate_content(post['content'])
    post['content'] = moderated_post_content

    #  Fetch Reactions (No moderation needed) 
    reactions = query_db('''
        SELECT reaction_type, COUNT(*) as count
        FROM reactions
        WHERE post_id = ?
        GROUP BY reaction_type
    ''', (post_id,))

    #  Fetch and Moderate Comments 
    comments_raw = query_db('SELECT c.id, c.content, c.created_at, u.username, u.id as user_id FROM comments c JOIN users u ON c.user_id = u.id WHERE c.post_id = ? ORDER BY c.created_at ASC', (post_id,))
    
    comments = [] # Create a new list for the moderated comments
    for comment_raw in comments_raw:
        comment = dict(comment_raw) # Convert to a dictionary
        # Moderate the content of each comment
        print(comment['content'])
        moderated_comment_content, _ = moderate_content(comment['content'])
        comment['content'] = moderated_comment_content
        comments.append(comment)

    # Pass the moderated data to the template
    return render_template('post_detail.html.j2',
                           post=post,
                           reactions=reactions,
                           comments=comments,
                           reaction_emojis=REACTION_EMOJIS,
                           reaction_types=REACTION_TYPES)

@app.route('/about')
def about():
    return render_template('about.html.j2')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html.j2')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        location = request.form.get('location', '')
        birthdate = request.form.get('birthdate', '')
        profile = request.form.get('profile', '')

        hashed_password = generate_password_hash(password)

        db = get_db()
        cur = db.cursor()
        try:
            cur.execute(
                'INSERT INTO users (username, password, location, birthdate, profile) VALUES (?, ?, ?, ?, ?)',
                (username, hashed_password, location, birthdate, profile)
            )
            db.commit()

            # 1. Get the ID of the user we just created.
            new_user_id = cur.lastrowid

            # 2. Add user info to the session cookie.
            session.clear() # Clear any old session data
            session['user_id'] = new_user_id
            session['username'] = username

            # 3. Flash a welcome message and redirect to the feed.
            flash(f'Welcome, {username}! Your account has been created.', 'success')
            return redirect(url_for('feed')) # Redirect to the main feed/dashboard

        except sqlite3.IntegrityError:
            flash('Username already taken. Please choose another one.', 'danger')
        finally:
            cur.close()
            db.close()
            
    return render_template('signup.html.j2')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        db.close()

        # 1. Check if the user exists.
        # 2. If user exists, use check_password_hash to securely compare the password.
        #    This function handles the salt and prevents timing attacks.
        if user and check_password_hash(user['password'], password):
            # Password is correct!
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Logged in successfully.', 'success')
            return redirect(url_for('feed'))
        else:
            # User does not exist or password was incorrect.
            flash('Invalid username or password.', 'danger')
            
    return render_template('login.html.j2')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/posts/<int:post_id>/comment', methods=['POST'])
def add_comment(post_id):
    """Handles adding a new comment to a specific post."""
    user_id = session.get('user_id')

    # Block access if user is not logged in
    if not user_id:
        flash('You must be logged in to comment.', 'danger')
        return redirect(url_for('login'))

    # Get content from the submitted form
    content = request.form.get('content')

    # Basic validation to ensure comment is not empty
    if content and content.strip():
        db = get_db()
        db.execute('INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)',
                   (post_id, user_id, content))
        db.commit()
        flash('Your comment was added.', 'success')
    else:
        flash('Comment cannot be empty.', 'warning')

    # Redirect back to the page the user came from (likely the post detail page)
    return redirect(request.referrer or url_for('post_detail', post_id=post_id))

@app.route('/comments/<int:comment_id>/delete', methods=['POST'])
def delete_comment(comment_id):
    """Handles deleting a comment."""
    user_id = session.get('user_id')

    # Block access if user is not logged in
    if not user_id:
        flash('You must be logged in to delete a comment.', 'danger')
        return redirect(url_for('login'))

    # Find the comment and the original post's author ID
    comment = query_db('''
        SELECT c.id, c.user_id, p.user_id as post_author_id
        FROM comments c
        JOIN posts p ON c.post_id = p.id
        WHERE c.id = ?
    ''', (comment_id,), one=True)

    # Check if the comment exists
    if not comment:
        flash('Comment not found.', 'danger')
        return redirect(request.referrer or url_for('feed'))

    # Security Check: Allow deletion if the user is the comment's author OR the post's author
    if user_id != comment['user_id'] and user_id != comment['post_author_id']:
        flash('You do not have permission to delete this comment.', 'danger')
        return redirect(request.referrer or url_for('feed'))

    # If all checks pass, proceed with deletion
    db = get_db()
    db.execute('DELETE FROM comments WHERE id = ?', (comment_id,))
    db.commit()

    flash('Comment successfully deleted.', 'success')
    # Redirect back to the page the user came from
    return redirect(request.referrer or url_for('feed'))

@app.route('/react', methods=['POST'])
def add_reaction():
    """Handles adding a new reaction or updating an existing one."""
    user_id = session.get('user_id')

    if not user_id:
        flash("You must be logged in to react.", "danger")
        return redirect(url_for('login'))

    post_id = request.form.get('post_id')
    new_reaction_type = request.form.get('reaction')

    if not post_id or not new_reaction_type:
        flash("Invalid reaction request.", "warning")
        return redirect(request.referrer or url_for('feed'))

    db = get_db()

    # Step 1: Check if a reaction from this user already exists on this post.
    existing_reaction = query_db('SELECT id FROM reactions WHERE post_id = ? AND user_id = ?',
                                 (post_id, user_id), one=True)

    if existing_reaction:
        # Step 2: If it exists, UPDATE the reaction_type.
        db.execute('UPDATE reactions SET reaction_type = ? WHERE id = ?',
                   (new_reaction_type, existing_reaction['id']))
    else:
        # Step 3: If it does not exist, INSERT a new reaction.
        db.execute('INSERT INTO reactions (post_id, user_id, reaction_type) VALUES (?, ?, ?)',
                   (post_id, user_id, new_reaction_type))

    db.commit()

    return redirect(request.referrer or url_for('feed'))

@app.route('/unreact', methods=['POST'])
def unreact():
    """Handles removing a user's reaction from a post."""
    user_id = session.get('user_id')

    if not user_id:
        flash("You must be logged in to unreact.", "danger")
        return redirect(url_for('login'))

    post_id = request.form.get('post_id')

    if not post_id:
        flash("Invalid unreact request.", "warning")
        return redirect(request.referrer or url_for('feed'))

    db = get_db()

    # Remove the reaction if it exists
    existing_reaction = query_db(
        'SELECT id FROM reactions WHERE post_id = ? AND user_id = ?',
        (post_id, user_id),
        one=True
    )

    if existing_reaction:
        db.execute('DELETE FROM reactions WHERE id = ?', (existing_reaction['id'],))
        db.commit()
        flash("Reaction removed.", "success")
    else:
        flash("No reaction to remove.", "info")

    return redirect(request.referrer or url_for('feed'))


@app.route('/u/<int:user_id>/follow', methods=['POST'])
def follow_user(user_id):
    """Handles the logic for the current user to follow another user."""
    follower_id = session.get('user_id')

    # Security: Ensure user is logged in
    if not follower_id:
        flash("You must be logged in to follow users.", "danger")
        return redirect(url_for('login'))

    # Security: Prevent users from following themselves
    if follower_id == user_id:
        flash("You cannot follow yourself.", "warning")
        return redirect(request.referrer or url_for('feed'))

    # Check if the user to be followed actually exists
    user_to_follow = query_db('SELECT id FROM users WHERE id = ?', (user_id,), one=True)
    if not user_to_follow:
        flash("The user you are trying to follow does not exist.", "danger")
        return redirect(request.referrer or url_for('feed'))
        
    db = get_db()
    try:
        # Insert the follow relationship. The PRIMARY KEY constraint will prevent duplicates if you've set one.
        db.execute('INSERT INTO follows (follower_id, followed_id) VALUES (?, ?)',
                   (follower_id, user_id))
        db.commit()
        username_to_follow = query_db('SELECT username FROM users WHERE id = ?', (user_id,), one=True)['username']
        flash(f"You are now following {username_to_follow}.", "success")
    except sqlite3.IntegrityError:
        flash("You are already following this user.", "info")

    return redirect(request.referrer or url_for('feed'))


@app.route('/u/<int:user_id>/unfollow', methods=['POST'])
def unfollow_user(user_id):
    """Handles the logic for the current user to unfollow another user."""
    follower_id = session.get('user_id')

    # Security: Ensure user is logged in
    if not follower_id:
        flash("You must be logged in to unfollow users.", "danger")
        return redirect(url_for('login'))

    db = get_db()
    cur = db.execute('DELETE FROM follows WHERE follower_id = ? AND followed_id = ?',
               (follower_id, user_id))
    db.commit()

    if cur.rowcount > 0:
        # cur.rowcount tells us if a row was actually deleted
        username_unfollowed = query_db('SELECT username FROM users WHERE id = ?', (user_id,), one=True)['username']
        flash(f"You have unfollowed {username_unfollowed}.", "success")
    else:
        # This case handles if someone tries to unfollow a user they weren't following
        flash("You were not following this user.", "info")

    # Redirect back to the page the user came from
    return redirect(request.referrer or url_for('feed'))

@app.route('/admin')
def admin_dashboard():
    """Displays the admin dashboard with users, posts, and comments, sorted by risk."""

    if session.get('username') != 'admin':
        flash("You do not have permission to access this page.", "danger")
        return redirect(url_for('feed'))

    RISK_LEVELS = { "HIGH": 5, "MEDIUM": 3, "LOW": 1 }
    PAGE_SIZE = 50

    def get_risk_profile(score):
        if score >= RISK_LEVELS["HIGH"]:
            return "HIGH", 3
        elif score >= RISK_LEVELS["MEDIUM"]:
            return "MEDIUM", 2
        elif score >= RISK_LEVELS["LOW"]:
            return "LOW", 1
        return "NONE", 0

    # Get pagination and current tab parameters
    try:
        users_page = int(request.args.get('users_page', 1))
        posts_page = int(request.args.get('posts_page', 1))
        comments_page = int(request.args.get('comments_page', 1))
        reports_page = int(request.args.get('reports_page', 1))
    except ValueError:
        users_page = 1
        posts_page = 1
        comments_page = 1
        reports_page = 1
    
    current_tab = request.args.get('tab', 'users') # Default to 'users' tab

    users_offset = (users_page - 1) * PAGE_SIZE
    
    # First, get all users to calculate risk, then apply pagination in Python
    # It's more complex to do this efficiently in SQL if risk calc is Python-side
    all_users_raw = query_db('SELECT id, username, profile, created_at FROM users')
    all_users = []
    for user in all_users_raw:
        user_dict = dict(user)
        user_risk_score = user_risk_analysis(user_dict['id'])
        risk_label, risk_sort_key = get_risk_profile(user_risk_score)
        user_dict['risk_label'] = risk_label
        user_dict['risk_sort_key'] = risk_sort_key
        user_dict['risk_score'] = min(5.0, round(user_risk_score, 2))
        all_users.append(user_dict)

    all_users.sort(key=lambda x: x['risk_score'], reverse=True)
    total_users = len(all_users)
    users = all_users[users_offset : users_offset + PAGE_SIZE]
    total_users_pages = (total_users + PAGE_SIZE - 1) // PAGE_SIZE

    # --- Posts Tab Data ---
    posts_offset = (posts_page - 1) * PAGE_SIZE
    total_posts_count = query_db('SELECT COUNT(*) as count FROM posts', one=True)['count']
    total_posts_pages = (total_posts_count + PAGE_SIZE - 1) // PAGE_SIZE

    posts_raw = query_db(f'''
        SELECT p.id, p.content, p.created_at, u.username, u.created_at as user_created_at
        FROM posts p JOIN users u ON p.user_id = u.id
        ORDER BY p.id DESC -- Order by ID for consistent pagination before risk sort
        LIMIT ? OFFSET ?
    ''', (PAGE_SIZE, posts_offset))
    posts = []
    for post in posts_raw:
        post_dict = dict(post)
        _, base_score = moderate_content(post_dict['content'])
        final_score = base_score 
        author_created_dt = post_dict['user_created_at']
        author_age_days = (datetime.utcnow() - author_created_dt).days
        if author_age_days < 7:
            final_score *= 1.5
        risk_label, risk_sort_key = get_risk_profile(final_score)
        post_dict['risk_label'] = risk_label
        post_dict['risk_sort_key'] = risk_sort_key
        post_dict['risk_score'] = round(final_score, 2)
        posts.append(post_dict)

    posts.sort(key=lambda x: x['risk_score'], reverse=True) # Sort after fetching and scoring

    # --- Comments Tab Data ---
    comments_offset = (comments_page - 1) * PAGE_SIZE
    total_comments_count = query_db('SELECT COUNT(*) as count FROM comments', one=True)['count']
    total_comments_pages = (total_comments_count + PAGE_SIZE - 1) // PAGE_SIZE

    comments_raw = query_db(f'''
        SELECT c.id, c.content, c.created_at, u.username, u.created_at as user_created_at
        FROM comments c JOIN users u ON c.user_id = u.id
        ORDER BY c.id DESC -- Order by ID for consistent pagination before risk sort
        LIMIT ? OFFSET ?
    ''', (PAGE_SIZE, comments_offset))
    comments = []
    for comment in comments_raw:
        comment_dict = dict(comment)
        _, score = moderate_content(comment_dict['content'])
        author_created_dt = comment_dict['user_created_at']
        author_age_days = (datetime.utcnow() - author_created_dt).days
        if author_age_days < 7:
            score *= 1.5
        risk_label, risk_sort_key = get_risk_profile(score)
        comment_dict['risk_label'] = risk_label
        comment_dict['risk_sort_key'] = risk_sort_key
        comment_dict['risk_score'] = round(score, 2)
        comments.append(comment_dict)

    comments.sort(key=lambda x: x['risk_score'], reverse=True) # Sort after fetching and scoring

    # --- Reports Tab Data ---
    reports_offset = (reports_page - 1) * PAGE_SIZE
    # Show unreviewed or reviewed reports (server-side filtering)
    reports_filter = request.args.get('reports_filter')
    if reports_filter == 'unreviewed':
        total_reports_count = query_db("SELECT COUNT(*) as count FROM reports WHERE status != 'reviewed'", one=True)['count']
        total_reports_pages = (total_reports_count + PAGE_SIZE - 1) // PAGE_SIZE

        reports_raw = query_db('''
            SELECT r.id, r.post_id, r.reporter_id, r.reason, r.status, r.created_at,
                   p.content as post_content, u.username as reporter_username
            FROM reports r
            LEFT JOIN posts p ON r.post_id = p.id
            LEFT JOIN users u ON r.reporter_id = u.id
            WHERE r.status != 'reviewed'
            ORDER BY r.created_at DESC
            LIMIT ? OFFSET ?
        ''', (PAGE_SIZE, reports_offset))
    else:
        total_reports_count = query_db('SELECT COUNT(*) as count FROM reports', one=True)['count']
        total_reports_pages = (total_reports_count + PAGE_SIZE - 1) // PAGE_SIZE

        reports_raw = query_db('''
            SELECT r.id, r.post_id, r.reporter_id, r.reason, r.status, r.created_at,
                   p.content as post_content, u.username as reporter_username
            FROM reports r
            LEFT JOIN posts p ON r.post_id = p.id
            LEFT JOIN users u ON r.reporter_id = u.id
            ORDER BY r.created_at DESC
            LIMIT ? OFFSET ?
        ''', (PAGE_SIZE, reports_offset))

    reports = []
    if reports_raw:
        for r in reports_raw:
            reports.append(dict(r))


    return render_template('admin.html.j2', 
                           users=users, 
                           posts=posts, 
                           comments=comments,
                           reports=reports,
                           
                           # Pagination for Users
                           users_page=users_page,
                           total_users_pages=total_users_pages,
                           users_has_next=(users_page < total_users_pages),
                           users_has_prev=(users_page > 1),

                           # Pagination for Posts
                           posts_page=posts_page,
                           total_posts_pages=total_posts_pages,
                           posts_has_next=(posts_page < total_posts_pages),
                           posts_has_prev=(posts_page > 1),

                           # Pagination for Comments
                           comments_page=comments_page,
                           total_comments_pages=total_comments_pages,
                           comments_has_next=(comments_page < total_comments_pages),
                           comments_has_prev=(comments_page > 1),

                           # Pagination for Reports
                           reports_page=reports_page,
                           total_reports_pages=total_reports_pages,
                           reports_has_next=(reports_page < total_reports_pages),
                           reports_has_prev=(reports_page > 1),

                           current_tab=current_tab,
                           PAGE_SIZE=PAGE_SIZE)



@app.route('/admin/delete/user/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    if session.get('username') != 'admin':
        flash("You do not have permission to perform this action.", "danger")
        return redirect(url_for('feed'))
        
    if user_id == session.get('user_id'):
        flash('You cannot delete your own account from the admin panel.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    db = get_db()
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    flash(f'User {user_id} and all their content has been deleted.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete/post/<int:post_id>', methods=['POST'])
def admin_delete_post(post_id):
    if session.get('username') != 'admin':
        flash("You do not have permission to perform this action.", "danger")
        return redirect(url_for('feed'))

    db = get_db()
    db.execute('DELETE FROM comments WHERE post_id = ?', (post_id,))
    db.execute('DELETE FROM reactions WHERE post_id = ?', (post_id,))
    db.execute('DELETE FROM posts WHERE id = ?', (post_id,))
    db.commit()
    flash(f'Post {post_id} has been deleted.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete/comment/<int:comment_id>', methods=['POST'])
def admin_delete_comment(comment_id):
    if session.get('username') != 'admin':
        flash("You do not have permission to perform this action.", "danger")
        return redirect(url_for('feed'))

    db = get_db()
    db.execute('DELETE FROM comments WHERE id = ?', (comment_id,))
    db.commit()
    flash(f'Comment {comment_id} has been deleted.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/report', methods=['POST'])
def report_post():
    """Allows a logged-in user to report a post."""
    user_id = session.get('user_id')
    if not user_id:
        flash('You must be logged in to report a post.', 'danger')
        return redirect(url_for('login'))

    post_id = request.form.get('post_id')
    # Support structured form: reason_type (select) + reason (details)
    reason_type = request.form.get('reason_type')
    reason_details = request.form.get('reason', '').strip()
    if reason_type:
        reason = f"{reason_type}: {reason_details}" if reason_details else reason_type
    else:
        reason = reason_details

    # Allow reports that are not tied to a specific post (post_id may be empty from navbar/global modal)
    # If a post_id is provided then prevent duplicate open reports by the same user on the same post
    if post_id:
        existing = query_db('SELECT 1 FROM reports WHERE post_id = ? AND reporter_id = ? AND status = ?', (post_id, user_id, 'open'), one=True)
        if existing:
            flash('You have already reported this post and it is pending review.', 'info')
            return redirect(request.referrer or url_for('feed'))

    db = get_db()
    # Insert NULL for post_id when not provided
    db.execute('INSERT INTO reports (post_id, reporter_id, reason) VALUES (?, ?, ?)', (post_id if post_id else None, user_id, reason))
    db.commit()
    flash('Thank you — the report has been submitted for review.', 'success')
    return redirect(request.referrer or url_for('feed'))

@app.route('/admin/report/<int:report_id>/action', methods=['POST'])
def admin_report_action(report_id):
    """Admin actions on a report: dismiss, mark_reviewed, delete_post."""
    if session.get('username') != 'admin':
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('feed'))

    action = request.form.get('action')
    db = get_db()

    if action == 'dismiss':
        db.execute('UPDATE reports SET status = ? WHERE id = ?', ('dismissed', report_id))
        flash('Report dismissed.', 'success')
    elif action == 'mark_reviewed':
        db.execute('UPDATE reports SET status = ? WHERE id = ?', ('reviewed', report_id))
        flash('Report marked as reviewed.', 'success')
    elif action == 'delete_post':
        report = query_db('SELECT post_id FROM reports WHERE id = ?', (report_id,), one=True)
        # sqlite3.Row does not implement dict.get(). Access fields using
        # mapping/indexing or convert to dict(). Check explicitly for None
        # because post_id may be NULL for global/site reports.
        if report and report['post_id'] is not None:
            post_id = report['post_id']
            # Delete post and related content
            db.execute('DELETE FROM comments WHERE post_id = ?', (post_id,))
            db.execute('DELETE FROM reactions WHERE post_id = ?', (post_id,))
            db.execute('DELETE FROM posts WHERE id = ?', (post_id,))
            db.execute('UPDATE reports SET status = ? WHERE id = ?', ('post_deleted', report_id))
            flash(f'Post {post_id} has been deleted.', 'success')
        else:
            flash('Report has no associated post to delete or post not found.', 'warning')
    else:
        flash('Unknown action.', 'warning')

    db.commit()
    return redirect(request.referrer or url_for('admin_dashboard', tab='reports'))

@app.route('/rules')
def rules():
    return render_template('rules.html.j2')

@app.template_global()
def loop_color(user_id):
    # Generate a pastel color based on user_id hash
    h = hashlib.md5(str(user_id).encode()).hexdigest()
    r = int(h[0:2], 16)
    g = int(h[2:4], 16)
    b = int(h[4:6], 16)
    return f'rgb({r % 128 + 80}, {g % 128 + 80}, {b % 128 + 80})'



# ----- Functions to be implemented are below

# Task 3.1
def recommend(user_id, filter_following):
    """
    Args:
        user_id: The ID of the current user.
        filter_following: Boolean, True if we only want to see recommendations from followed users.

    Returns:
        A list of 5 recommended posts, in reverse-chronological order.

    To test whether your recommendation algorithm works, let's pretend we like the DIY topic. Here are some users that often post DIY comment and a few example posts. Make sure your account did not engage with anything else. You should test your algorithm with these and see if your recommendation algorithm picks up on your interest in DIY and starts showing related content.
    
    Users: @starboy99, @DancingDolphin, @blogger_bob
    Posts: 1810, 1875, 1880, 2113
    
    Materials: 
    - https://www.nvidia.com/en-us/glossary/recommendation-system/
    - http://www.configworks.com/mz/handout_recsys_sac2010.pdf
    - https://www.researchgate.net/publication/227268858_Recommender_Systems_Handbook

    After reading through the materials, I decided to implement a hybrid recommendation system that combines content-based filtering with collaborative filtering, explicitly weighting different types of user feedback, and improving cold start handling.

    Besides, I also implemented several NLP techniques:
    - Stop word filtering
    - TF weighting
    - User similarity via collaborative filtering

    After tried to follow Users with DIY interests and react to their posts, the recommendation algorithm started to show more DIY-related posts in the recommend tab.
    """
    
    # Cold Start Strategy
    """
    If the user is not logged in, I simply return the 5 most recent posts by selecting from the posts table ordered by created_at DESC
    """
    if not user_id:
        recent_posts = query_db('''
            SELECT p.id, p.content, p.created_at, u.username, u.id as user_id
            FROM posts p
            JOIN users u ON p.user_id = u.id
            ORDER BY p.created_at DESC
            LIMIT 5
        ''')
        return recent_posts if recent_posts else []
    
    # Check if user has interactions
    """
    This query checks if the user has any reactions recorded in the reactions table
    The WHERE r.user_id = ? clause get the user_id that are passed into and filters reactions to only those made by the current user
    """
    user_reactions = query_db('''
        SELECT p.content, r.reaction_type
        FROM reactions r
        JOIN posts p ON r.post_id = p.id
        WHERE r.user_id = ?
    ''', (user_id,))
    
    if not user_reactions:
        if filter_following:
            """
            This query fetch the most recent posts from users that the current user follows by joining the posts, users, and follows tables. The WHERE f.follower_id = ? clause filters the posts to only those made by users that the current user follows
            """
            qr = query_db('''
                SELECT DISTINCT p.id, p.content, p.created_at, u.username, u.id as user_id
                FROM posts p
                JOIN users u ON p.user_id = u.id
                JOIN follows f ON p.user_id = f.followed_id
                WHERE f.follower_id = ? AND p.user_id != ?
                ORDER BY p.created_at DESC
                LIMIT 5
            ''', (user_id, user_id))
        else:
            """
            This query fetches the 5 most recent posts from all users except the current user (WHERE p.user_id != ?) by joining the posts and users tables
            """
            qr = query_db('''
                SELECT p.id, p.content, p.created_at, u.username, u.id as user_id
                FROM posts p
                JOIN users u ON p.user_id = u.id
                WHERE p.user_id != ?
                ORDER BY p.created_at DESC
                LIMIT 5
            ''', (user_id,))
        return qr if qr else []
    
    """
    I decided to assign different weights to different reaction types to reflect their significance in indicating user interest
    """
    REACTION_WEIGHTS = {
        'love': 2.0, 'like': 1.5, 'wow': 1.2,
        'laugh': 1.0, 'sad': 0.3, 'angry': 0.1
    }
    
    """
    To find interest keywords, I analyze the content of posts the user has reacted to, applying weights based on reaction types. I also implement stop word filtering to focus on meaningful keywords and give more weight to hashtags
    """
    interest_keywords = {}
    for reaction in user_reactions:
        weight = REACTION_WEIGHTS.get(reaction['reaction_type'], 0.5)
        words = reaction['content'].lower().split()
        
        for word in words:
            clean_word = ''.join(c for c in word if c.isalnum() or c == '#')
            # Stop word filtering
            if len(clean_word) >= 3 and clean_word.lower() not in STOP_WORDS:
                if clean_word.startswith('#'):
                    weight *= 2  # Hashtags are strong signals
                interest_keywords[clean_word] = interest_keywords.get(clean_word, 0) + weight
    
    """
    This query identifies users with same interest by finding common reactions on the same posts. It count the number of common likes between the current user and other users, filtering for those with at least 2 common likes by joining the reactions table on itself and than grouping by the other user's ID. 5 similar users will be selected based on the highest count of common likes
    """
    similar_users = query_db('''
        SELECT r2.user_id, COUNT(*) as common_likes
        FROM reactions r1
        JOIN reactions r2 ON r1.post_id = r2.post_id
        WHERE r1.user_id = ? AND r2.user_id != ?
        GROUP BY r2.user_id
        HAVING common_likes >= 2
        ORDER BY common_likes DESC
        LIMIT 5
    ''', (user_id, user_id))
    
    similar_user_ids = [u['user_id'] for u in similar_users] if similar_users else []
    
    # Exclude those from recommendations)
    reacted_post_ids = query_db('''
        SELECT post_id FROM reactions WHERE user_id = ?
    ''', (user_id,))

    # This is the react ids of the posts the user has already reacted to
    reacted_ids = [str(row['post_id']) for row in reacted_post_ids] if reacted_post_ids else []
    
    """
    I fetch candidate posts based on whether to filter by followed users or not, and exclude posts the user has already reacted to. The queries join the posts and users tables, and order the results by creation date to prioritize recent content
    
    The flow for this section is as follows:
    - If filter_following is True:
        - If reacted_ids is not empty, fetch posts from followed users excluding reacted posts
        - Else, fetch posts from followed users
    - Else:
        - If reacted_ids is not empty, fetch posts from all users excluding reacted posts
        - Else, fetch posts from all users
    """
    if filter_following:
        if reacted_ids:
            candidates = query_db('''
                SELECT DISTINCT p.id, p.content, p.created_at, u.username, u.id as user_id
                FROM posts p
                JOIN users u ON p.user_id = u.id
                JOIN follows f ON p.user_id = f.followed_id
                WHERE f.follower_id = ? AND p.user_id != ?
                  AND p.id NOT IN ({})
                ORDER BY p.created_at DESC
                LIMIT 100
            '''.format(','.join('?' * len(reacted_ids))), (user_id, user_id) + tuple(reacted_ids))
        else:
            candidates = query_db('''
                SELECT DISTINCT p.id, p.content, p.created_at, u.username, u.id as user_id
                FROM posts p
                JOIN users u ON p.user_id = u.id
                JOIN follows f ON p.user_id = f.followed_id
                WHERE f.follower_id = ? AND p.user_id != ?
                ORDER BY p.created_at DESC
                LIMIT 100
            ''', (user_id, user_id))
    else:
        if reacted_ids:
            candidates = query_db('''
                SELECT p.id, p.content, p.created_at, u.username, u.id as user_id
                FROM posts p
                JOIN users u ON p.user_id = u.id
                WHERE p.user_id != ?
                  AND p.id NOT IN ({})
                ORDER BY p.created_at DESC
                LIMIT 200
            '''.format(','.join('?' * len(reacted_ids))), (user_id,) + tuple(reacted_ids))
        else:
            candidates = query_db('''
                SELECT p.id, p.content, p.created_at, u.username, u.id as user_id
                FROM posts p
                JOIN users u ON p.user_id = u.id
                WHERE p.user_id != ?
                ORDER BY p.created_at DESC
                LIMIT 200
            ''', (user_id, user_id))
    
    if not candidates:
        return []
    
    scored_posts = []
    
    for post in candidates:
        score = 0
        
        """
        Content-Based Filtering
        I analyze the content of each candidate post for keywords that match the user's interests, increamenting the score based on the presence and weight of these keywords
        """
        post_words = post['content'].lower().split()
        for word in post_words:
            clean_word = ''.join(c for c in word if c.isalnum() or c == '#')
            if clean_word in interest_keywords:
                score += interest_keywords[clean_word]
        
        """
        Collaborative Filtering
        I check if any similar users have liked the candidate post. If so, I increase the score
        """
        if similar_user_ids:
            for similar_user in similar_user_ids:
                liked_by_similar = query_db('''
                    SELECT 1 FROM reactions 
                    WHERE post_id = ? AND user_id = ?
                    LIMIT 1
                ''', (post['id'], similar_user), one=True)
                if liked_by_similar:
                    score += 2
        
        """
        I also increase the score for more recent posts to prioritize fresh content
        """
        post_date = post['created_at'] if isinstance(post['created_at'], datetime) else datetime.strptime(post['created_at'], '%Y-%m-%d %H:%M:%S')
        days_old = (datetime.utcnow() - post_date).days
        if days_old < 7:
            score += 1
        elif days_old < 30:
            score += 0.5
        
        scored_posts.append((post, score))
    
    scored_posts.sort(key=lambda x: x[1], reverse=True)
    top_posts = [post for post, score in scored_posts[:5]]
    
    top_posts.sort(key=lambda x: x['created_at'], reverse=True)
    
    return top_posts

# Task 3.2
def user_risk_analysis(user_id):
    """
    Args:
        user_id: The ID of the user on which we perform risk analysis.

    Returns:
        A float number score showing the risk associated with this user. There are no strict rules or bounds to this score, other than that a score of less than 1.0 means no risk, 1.0 to 3.0 is low risk, 3.0 to 5.0 is medium risk and above 5.0 is high risk. (An upper bound of 5.0 is applied to this score elsewhere in the codebase) 
        
        You will be able to check the scores by logging in with the administrator account:
            username: admin
            password: admin
        Then, navigate to the /admin endpoint. (http://localhost:8080/admin)
    """

    return 0.0
    
    user = query_db('SELECT profile, created_at FROM users WHERE id = ?', (user_id,), one=True)
    if not user:
        return 0.0
    
    # Step 1: I moderate the user's profile description and get the score from it
    profile_text = user['profile'] if user['profile'] else ''
    _, profile_score = moderate_content(profile_text)
    
    # Step 2: I moderate all posts made by the user and calculate the average post score by iterating through each post, moderating its content, and collecting the scores to compute the average
    posts = query_db('SELECT content FROM posts WHERE user_id = ?', (user_id,))
    if posts and len(posts) > 0:
        post_scores = []
        for post in posts:
            _, post_score = moderate_content(post['content'])
            post_scores.append(post_score)
        average_post_score = sum(post_scores) / len(post_scores)
    else:
        average_post_score = 0.0
    
    # Step 3: I moderate all comments and get the average comment score just like posts
    comments = query_db('SELECT content FROM comments WHERE user_id = ?', (user_id,))
    if comments and len(comments) > 0:
        comment_scores = []
        for comment in comments:
            _, comment_score = moderate_content(comment['content'])
            comment_scores.append(comment_score)
        average_comment_score = sum(comment_scores) / len(comment_scores)
    else:
        average_comment_score = 0.0
    
    # Step 4: I calculate the content risk score using weighted contributions from profile, posts, and comments
    content_risk_score = (profile_score * 1) + (average_post_score * 3) + (average_comment_score * 1)
    
    # Step 5: I adjust the risk score based on account age
    user_created_at = user['created_at']
    account_age_days = (datetime.utcnow() - user_created_at).days
    
    if account_age_days < 7:
        user_risk_score = content_risk_score * 1.5
    elif account_age_days < 30:
        user_risk_score = content_risk_score * 1.2
    else:
        user_risk_score = content_risk_score
    
    """
    Additional Risk Measure
    This detects automated spam bots that post at unnaturally high frequencies.
    I decided to implement this based on research into bot behavior patterns.
    There are some reason that this might affect negatively to the platform:
    - Bots can post clean content that evades keyword filters
    - Make the platform less appealing to real users
    - Bots can flood the platform with spam even if content seems clean 
    """
    
    suspicious_activity_score = 0.0
    
    """
    First, I check the posting frequency by calculating the average number of posts per day since account creation
    """
    if posts and account_age_days > 0:
        posts_per_day = len(posts) / max(account_age_days, 1)
        
        # Normal users rarely post more than 10 times per day consistently
        if posts_per_day > 10:
            suspicious_activity_score += 0.5
        
        # Accounts posting 20+ times per day are almost certainly automated bots
        if posts_per_day > 20:
            suspicious_activity_score += 0.5
    
    user_risk_score += suspicious_activity_score
    
    # Step 6
    final_score = min(5.0, user_risk_score)
    
    return final_score

# Task 3.3
def moderate_content(content):
    """
    Args
        content: the text content of a post or comment to be moderated.
        
    Returns: 
        A tuple containing the moderated content (string) and a severity score (float). There are no strict rules or bounds to the severity score, other than that a score of less than 1.0 means no risk, 1.0 to 3.0 is low risk, 3.0 to 5.0 is medium risk and above 5.0 is high risk.
    
    This function moderates a string of content and calculates a severity score based on
    rules loaded from the 'censorship.dat' file. These are already loaded as TIER1_WORDS, TIER2_PHRASES and TIER3_WORDS. Tier 1 corresponds to strong profanity, Tier 2 to scam/spam phrases and Tier 3 to mild profanity.
    
    You will be able to check the scores by logging in with the administrator account:
            username: admin
            password: admin
    Then, navigate to the /admin endpoint. (http://localhost:8080/admin)
    """

    # Handle empty or invalid content
    if not content or not isinstance(content, str):
        return content, 0.0
    
    moderated_content = content
    score = 0.0
    
    """
    Rule 1.1.1
    A case-insensitive, whole-word search is performed against the Tier 1 Word List. If a match is found, the function immediately returns the string [content removed due to severe violation] and a fixed Content Score of 5.0.
    """
    for word in TIER1_WORDS:
        pattern = r'\b' + re.escape(word) + r'\b'
        if re.search(pattern, content, re.IGNORECASE):
            return "[content removed due to severe violation]", 5.0
    
    """
    Rule 1.1.2
    If no Tier 1 match is found, a case-insensitive, whole-phrase search is performed against the Tier 2 Phrase List. If a match is found, the function immediately returns the string [content removed due to spam/scam policy] and a fixed Content Score of 5.0.
    """
    for phrase in TIER2_PHRASES:
        # Use word boundaries for whole phrase matching
        pattern = r'\b' + re.escape(phrase) + r'\b'
        if re.search(pattern, content, re.IGNORECASE):
            return "[content removed due to spam/scam policy]", 5.0
    
    """
    Rule 1.2.1
    Each case-insensitive, whole-word match from the Tier 3 Word List is replaced with asterisks (*) equal to its length. The Content Score is incremented by +2.0 for each match.
    """
    for word in TIER3_WORDS:
        pattern = r'\b' + re.escape(word) + r'\b'
        matches = re.findall(pattern, moderated_content, re.IGNORECASE)
        if matches:
            score += len(matches) * 2.0
            def replace_with_asterisks(match):
                return '*' * len(match.group(0))
            moderated_content = re.sub(pattern, replace_with_asterisks, moderated_content, flags=re.IGNORECASE)
    
    """
    Rule 1.2.2
    Each detected URL is replaced with [link removed]. The Content Score is incremented by +2.0 for each match.
    
    After detecting some odd URLs, I decided to implement some enhanced URL detection that checks for:
    - Full URLs with and without http(s) protocol
    - Obfuscated URLs: example[.]com, domain[dot]org (spammer technique to bypass filters)
    - Common TLDs: .com, .org, .net, .edu, .gov, .io, .co.uk, .co.jp, etc.
    - Excludes URLs inside square brackets [example.com] to avoid false positives


    # Here I de-obfuscate URLs by replacing [.] and [dot] with actual dots
    # I temporarily convert these to domain.com so our pattern can detect them
    """
    deobfuscated_content = moderated_content
    deobfuscated_content = re.sub(r'\[\.\]', '.', deobfuscated_content)
    deobfuscated_content = re.sub(r'\[dot\]', '.', deobfuscated_content, flags=re.IGNORECASE)

    """
    Regex pattern explaination:
    https?://[^\s\[\]]+  -> Matches full URLs starting with http:// or https://
    www\.[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9] -> Matches URLs starting with www.
    \b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-z]{2,}(?:\.[a-z]{2,})? -> Matches domain.abc or domain.abc.abc
    """
    url_pattern = r'(?<![@\[])(?:https?://[^\s\[\]]+|www\.[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9](?:/[^\s\[\]]*)?|\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-z]{2,}(?:\.[a-z]{2,})?(?:/[^\s\[\]]*)?)(?!\])'
    
    urls = re.findall(url_pattern, deobfuscated_content, re.IGNORECASE)
    if urls:
        url_count = len(urls)
        score += url_count * 2.0
        moderated_content = re.sub(url_pattern, '[link removed]', deobfuscated_content, flags=re.IGNORECASE)
    
    """
    Rule 1.2.3
    If content has >15 alphabetic characters and >70% are uppercase, the Content Score is incremented by a fixed value of +0.5. The content is not modified.
    """
    alphabetic_chars = [c for c in moderated_content if c.isalpha()]
    if len(alphabetic_chars) > 15:
        uppercase_count = sum(1 for c in alphabetic_chars if c.isupper())
        uppercase_ratio = uppercase_count / len(alphabetic_chars)
        if uppercase_ratio > 0.7:
            score += 0.5
    
    """
    Additional measure: Giveaway/Contest Spam Detection
    After investigating the dataset, I found that giveaway and contest spam is a probable issue on this platform, because it can lead to harmful outcomes for users. To name a few: leading to phising attempts, create false expectations and disappointment, etc.
    
    Real examples from the platform that currently score 0.0 but are clearly spam:
    - "FLASH GIVEAWAY? Click the link in our bio to claim your PS5! Only 100 units left!"
    - "We're giving away $1000 to 5 lucky people! Like, share, and comment 'WIN' to enter!"
    
    Penalty: +2.0 (severe spam that harms user trust and security)
    """
    
    # Define giveaway spam patterns with their regex
    giveaway_patterns = [
        r'\bgiveaway\b',
        r'\bgiving away\b',
        r'\bwin free\b',   
        r'\bclaim your\b', 
        r'\bclick\s+(the\s+)?link\b',
        r'\b(dm|message)\s+(us|me)\b',
        r'\bfollow\s+and\b',          
        r'\benter\s+to\s+win\b',      
        r'\bonly\s+\d+\s+(left|units)\b',
        r'\bflash\s+giveaway\b',         
        r'\bcontest\s+alert\b',          
        r'\blucky\s+(winner|people)\b',  
    ]
    
    giveaway_matches = 0
    content_lower = content.lower()
    
    """
    I count the number of giveaway-related patterns matched in the content. If 2 or more patterns are found, I consider it as giveaway spam and increment the score by +2.0
    """
    for pattern in giveaway_patterns:
        if re.search(pattern, content_lower):
            giveaway_matches += 1
    
    if giveaway_matches >= 2:
        score += 2.0
    
    return moderated_content, score


if __name__ == '__main__':
    app.run(debug=True, port=8080)

