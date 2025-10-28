from flask import Flask, request, session, redirect, url_for, render_template, flash, jsonify
import boto3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import logging
import os
import uuid
from dotenv import load_dotenv
from botocore.exceptions import ClientError

# Load environment variables
load_dotenv()

# ---------------------------------------
# Flask App Initialization
# ---------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'indiestream_secret_key_change_in_production')

# ---------------------------------------
# App Configuration
# ---------------------------------------
AWS_REGION_NAME = os.environ.get('AWS_REGION_NAME', 'eu-north-1')

# Table Names from .env
USERS_TABLE_NAME = os.environ.get('USERS_TABLE_NAME', 'IndieStreamUsers')
VIDEOS_TABLE_NAME = os.environ.get('VIDEOS_TABLE_NAME', 'IndieStreamVideos')
SEARCH_INDEX_TABLE_NAME = os.environ.get('SEARCH_INDEX_TABLE_NAME', 'IndieStreamSearchIndex')

# ---------------------------------------
# AWS Resources
# ---------------------------------------
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION_NAME)

# DynamoDB Tables
users_table = dynamodb.Table(USERS_TABLE_NAME)
videos_table = dynamodb.Table(VIDEOS_TABLE_NAME)
search_index_table = dynamodb.Table(SEARCH_INDEX_TABLE_NAME)

# ---------------------------------------
# Logging
# ---------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("indiestream.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ---------------------------------------
# Helper Functions
# ---------------------------------------
def is_logged_in():
    """Check if user is logged in"""
    return 'user_id' in session

def get_current_user():
    """Get current logged-in user details"""
    if not is_logged_in():
        return None
    try:
        response = users_table.get_item(Key={'user_id': session['user_id']})
        return response.get('Item')
    except Exception as e:
        logger.error(f"Error fetching user: {e}")
        return None

def require_login(f):
    """Decorator to require login for routes"""
    def decorated_function(*args, **kwargs):
        if not is_logged_in():
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def update_search_index(video_id, video_data):
    """Update search index for faster queries"""
    try:
        search_terms = []
        
        # Add title words
        if video_data.get('title'):
            search_terms.extend(video_data['title'].lower().split())
        
        # Add genre tags
        if video_data.get('genre_tags'):
            search_terms.extend([tag.lower() for tag in video_data['genre_tags']])
        
        # Add creator name
        if video_data.get('creator_name'):
            search_terms.extend(video_data['creator_name'].lower().split())
        
        # Store unique search terms
        for term in set(search_terms):
            if len(term) >= 2:  # Only index terms with 2+ characters
                search_index_table.put_item(
                    Item={
                        'search_term': term,
                        'video_id': video_id,
                        'title': video_data.get('title', ''),
                        'indexed_at': datetime.now().isoformat()
                    }
                )
        
        logger.info(f"Search index updated for video {video_id}")
    except Exception as e:
        logger.error(f"Failed to update search index: {e}")

# ---------------------------------------
# Routes
# ---------------------------------------

# Home Page
@app.route('/')
def index():
    """Landing page for IndieStream"""
    if is_logged_in():
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# User Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    """Register new content creator"""
    if is_logged_in():
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # Validate required fields
        required_fields = ['username', 'email', 'password', 'full_name']
        for field in required_fields:
            if not request.form.get(field):
                flash(f'Please fill in the {field.replace("_", " ")} field', 'danger')
                return render_template('register.html')
        
        # Check password confirmation
        if request.form['password'] != request.form.get('confirm_password', ''):
            flash('Passwords do not match', 'danger')
            return render_template('register.html')
        
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        full_name = request.form['full_name']
        bio = request.form.get('bio', '')
        
        # Check if username or email already exists
        try:
            # Check username
            existing_user = users_table.scan(
                FilterExpression="username = :username",
                ExpressionAttributeValues={":username": username}
            ).get('Items', [])
            
            if existing_user:
                flash('Username already taken', 'danger')
                return render_template('register.html')
            
            # Check email
            existing_email = users_table.scan(
                FilterExpression="email = :email",
                ExpressionAttributeValues={":email": email}
            ).get('Items', [])
            
            if existing_email:
                flash('Email already registered', 'danger')
                return render_template('register.html')
            
            # Create new user
            user_id = str(uuid.uuid4())
            users_table.put_item(
                Item={
                    'user_id': user_id,
                    'username': username,
                    'email': email,
                    'password': password,
                    'full_name': full_name,
                    'bio': bio,
                    'total_videos': 0,
                    'total_views': 0,
                    'created_at': datetime.now().isoformat(),
                    'account_status': 'active'
                }
            )
            
            logger.info(f"New user registered: {username}")
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            logger.error(f"Registration error: {e}")
            flash('An error occurred during registration. Please try again.', 'danger')
            return render_template('register.html')
    
    return render_template('register.html')

# User Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if is_logged_in():
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        if not request.form.get('username') or not request.form.get('password'):
            flash('Please enter both username and password', 'danger')
            return render_template('login.html')
        
        username = request.form['username']
        password = request.form['password']
        
        try:
            # Find user by username
            response = users_table.scan(
                FilterExpression="username = :username",
                ExpressionAttributeValues={":username": username}
            )
            
            users = response.get('Items', [])
            
            if users and check_password_hash(users[0]['password'], password):
                user = users[0]
                
                # Check account status
                if user.get('account_status') != 'active':
                    flash('Your account has been suspended. Please contact support.', 'danger')
                    return render_template('login.html')
                
                # Set session
                session['user_id'] = user['user_id']
                session['username'] = user['username']
                session['full_name'] = user['full_name']
                
                flash(f'Welcome back, {user["full_name"]}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password', 'danger')
                
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash('An error occurred during login. Please try again.', 'danger')
    
    return render_template('login.html')

# User Logout
@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('index'))

# Dashboard
@app.route('/dashboard')
@require_login
def dashboard():
    """Creator dashboard showing their videos and stats"""
    try:
        user = get_current_user()
        
        # Get user's videos using GSI or scan
        try:
            response = videos_table.query(
                IndexName='CreatorIndex',
                KeyConditionExpression="creator_id = :creator_id",
                ExpressionAttributeValues={":creator_id": session['user_id']}
            )
            videos = response.get('Items', [])
        except:
            # Fallback to scan if GSI doesn't exist
            response = videos_table.scan(
                FilterExpression="creator_id = :creator_id",
                ExpressionAttributeValues={":creator_id": session['user_id']}
            )
            videos = response.get('Items', [])
        
        # Sort videos by upload date
        videos.sort(key=lambda x: x.get('uploaded_at', ''), reverse=True)
        
        # Calculate stats
        total_videos = len(videos)
        total_views = sum(video.get('view_count', 0) for video in videos)
        
        return render_template('dashboard.html', 
                             user=user, 
                             videos=videos,
                             total_videos=total_videos,
                             total_views=total_views)
    
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        flash('Error loading dashboard', 'danger')
        return redirect(url_for('index'))

# Upload Video Metadata
@app.route('/upload', methods=['GET', 'POST'])
@require_login
def upload_video():
    """Upload new video metadata"""
    if request.method == 'POST':
        # Validate required fields
        required_fields = ['title', 'description', 'duration']
        for field in required_fields:
            if not request.form.get(field):
                flash(f'Please fill in the {field} field', 'danger')
                return render_template('upload.html')
        
        try:
            # Get form data
            title = request.form['title']
            description = request.form['description']
            duration = request.form['duration']
            genre_tags = request.form.get('genre_tags', '').split(',')
            genre_tags = [tag.strip() for tag in genre_tags if tag.strip()]
            license_type = request.form.get('license_type', 'Standard')
            video_url = request.form.get('video_url', '')
            thumbnail_url = request.form.get('thumbnail_url', '')
            
            user = get_current_user()
            
            # Create video metadata
            video_id = str(uuid.uuid4())
            video_data = {
                'video_id': video_id,
                'creator_id': session['user_id'],
                'creator_name': user['username'],
                'title': title,
                'description': description,
                'duration': duration,
                'genre_tags': genre_tags,
                'license_type': license_type,
                'video_url': video_url,
                'thumbnail_url': thumbnail_url,
                'view_count': 0,
                'like_count': 0,
                'uploaded_at': datetime.now().isoformat(),
                'status': 'published'
            }
            
            # Store in DynamoDB
            videos_table.put_item(Item=video_data)
            
            # Update search index
            update_search_index(video_id, video_data)
            
            # Update user's video count
            users_table.update_item(
                Key={'user_id': session['user_id']},
                UpdateExpression='SET total_videos = total_videos + :inc',
                ExpressionAttributeValues={':inc': 1}
            )
            
            logger.info(f"Video uploaded: {video_id} by {session['username']}")
            flash('Video metadata uploaded successfully!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            logger.error(f"Upload error: {e}")
            flash('Error uploading video metadata. Please try again.', 'danger')
            return render_template('upload.html')
    
    return render_template('upload.html')

# View Video Details
@app.route('/video/<video_id>')
def view_video(video_id):
    """View detailed video information"""
    try:
        response = videos_table.get_item(Key={'video_id': video_id})
        video = response.get('Item')
        
        if not video:
            flash('Video not found', 'danger')
            return redirect(url_for('browse'))
        
        # Increment view count
        videos_table.update_item(
            Key={'video_id': video_id},
            UpdateExpression='SET view_count = view_count + :inc',
            ExpressionAttributeValues={':inc': 1}
        )
        
        video['view_count'] = video.get('view_count', 0) + 1
        
        # Get creator info
        creator_response = users_table.get_item(Key={'user_id': video['creator_id']})
        creator = creator_response.get('Item', {})
        
        return render_template('view_video.html', video=video, creator=creator)
        
    except Exception as e:
        logger.error(f"View video error: {e}")
        flash('Error loading video', 'danger')
        return redirect(url_for('browse'))

# Edit Video Metadata
@app.route('/video/<video_id>/edit', methods=['GET', 'POST'])
@require_login
def edit_video(video_id):
    """Edit video metadata"""
    try:
        response = videos_table.get_item(Key={'video_id': video_id})
        video = response.get('Item')
        
        if not video:
            flash('Video not found', 'danger')
            return redirect(url_for('dashboard'))
        
        # Check ownership
        if video['creator_id'] != session['user_id']:
            flash('You are not authorized to edit this video', 'danger')
            return redirect(url_for('dashboard'))
        
        if request.method == 'POST':
            # Update video metadata
            title = request.form['title']
            description = request.form['description']
            duration = request.form['duration']
            genre_tags = request.form.get('genre_tags', '').split(',')
            genre_tags = [tag.strip() for tag in genre_tags if tag.strip()]
            license_type = request.form.get('license_type', video.get('license_type'))
            
            videos_table.update_item(
                Key={'video_id': video_id},
                UpdateExpression='SET title = :title, description = :desc, duration = :dur, genre_tags = :tags, license_type = :license, updated_at = :updated',
                ExpressionAttributeValues={
                    ':title': title,
                    ':desc': description,
                    ':dur': duration,
                    ':tags': genre_tags,
                    ':license': license_type,
                    ':updated': datetime.now().isoformat()
                }
            )
            
            # Update search index
            video['title'] = title
            video['genre_tags'] = genre_tags
            update_search_index(video_id, video)
            
            flash('Video updated successfully!', 'success')
            return redirect(url_for('view_video', video_id=video_id))
        
        return render_template('edit_video.html', video=video)
        
    except Exception as e:
        logger.error(f"Edit video error: {e}")
        flash('Error editing video', 'danger')
        return redirect(url_for('dashboard'))

# Delete Video
@app.route('/video/<video_id>/delete', methods=['POST'])
@require_login
def delete_video(video_id):
    """Delete video metadata"""
    try:
        response = videos_table.get_item(Key={'video_id': video_id})
        video = response.get('Item')
        
        if not video:
            flash('Video not found', 'danger')
            return redirect(url_for('dashboard'))
        
        # Check ownership
        if video['creator_id'] != session['user_id']:
            flash('You are not authorized to delete this video', 'danger')
            return redirect(url_for('dashboard'))
        
        # Delete video
        videos_table.delete_item(Key={'video_id': video_id})
        
        # Update user's video count
        users_table.update_item(
            Key={'user_id': session['user_id']},
            UpdateExpression='SET total_videos = total_videos - :dec',
            ExpressionAttributeValues={':dec': 1}
        )
        
        logger.info(f"Video deleted: {video_id}")
        flash('Video deleted successfully', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        logger.error(f"Delete video error: {e}")
        flash('Error deleting video', 'danger')
        return redirect(url_for('dashboard'))

# Browse All Videos
@app.route('/browse')
def browse():
    """Browse all published videos"""
    try:
        # Get filter parameters
        genre_filter = request.args.get('genre', '')
        sort_by = request.args.get('sort', 'recent')
        
        # Scan videos (in production, use pagination)
        response = videos_table.scan(
            FilterExpression='#status = :status',
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={':status': 'published'}
        )
        videos = response.get('Items', [])
        
        # Apply genre filter
        if genre_filter:
            videos = [v for v in videos if genre_filter.lower() in [tag.lower() for tag in v.get('genre_tags', [])]]
        
        # Sort videos
        if sort_by == 'recent':
            videos.sort(key=lambda x: x.get('uploaded_at', ''), reverse=True)
        elif sort_by == 'popular':
            videos.sort(key=lambda x: x.get('view_count', 0), reverse=True)
        elif sort_by == 'title':
            videos.sort(key=lambda x: x.get('title', '').lower())
        
        # Get unique genres for filter
        all_genres = set()
        for video in response.get('Items', []):
            all_genres.update(video.get('genre_tags', []))
        
        return render_template('browse.html', 
                             videos=videos, 
                             genres=sorted(all_genres),
                             current_genre=genre_filter,
                             current_sort=sort_by)
        
    except Exception as e:
        logger.error(f"Browse error: {e}")
        flash('Error loading videos', 'danger')
        return render_template('browse.html', videos=[], genres=[])

# Search Videos
@app.route('/search')
def search():
    """Search videos by title, tags, or creator"""
    query = request.args.get('q', '').strip().lower()
    
    if not query:
        flash('Please enter a search query', 'warning')
        return redirect(url_for('browse'))
    
    try:
        # Search in multiple fields
        response = videos_table.scan()
        all_videos = response.get('Items', [])
        
        results = []
        for video in all_videos:
            # Search in title
            if query in video.get('title', '').lower():
                results.append(video)
                continue
            
            # Search in genre tags
            if any(query in tag.lower() for tag in video.get('genre_tags', [])):
                results.append(video)
                continue
            
            # Search in creator name
            if query in video.get('creator_name', '').lower():
                results.append(video)
                continue
            
            # Search in description
            if query in video.get('description', '').lower():
                results.append(video)
        
        # Remove duplicates and sort by relevance
        results = list({v['video_id']: v for v in results}.values())
        results.sort(key=lambda x: x.get('view_count', 0), reverse=True)
        
        return render_template('search_results.html', 
                             videos=results, 
                             query=query,
                             result_count=len(results))
        
    except Exception as e:
        logger.error(f"Search error: {e}")
        flash('Error performing search', 'danger')
        return redirect(url_for('browse'))

# User Profile
@app.route('/profile', methods=['GET', 'POST'])
@require_login
def profile():
    """View and edit user profile"""
    try:
        user = get_current_user()
        
        if request.method == 'POST':
            full_name = request.form.get('full_name')
            bio = request.form.get('bio', '')
            
            users_table.update_item(
                Key={'user_id': session['user_id']},
                UpdateExpression='SET full_name = :name, bio = :bio, updated_at = :updated',
                ExpressionAttributeValues={
                    ':name': full_name,
                    ':bio': bio,
                    ':updated': datetime.now().isoformat()
                }
            )
            
            session['full_name'] = full_name
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))
        
        return render_template('profile.html', user=user)
        
    except Exception as e:
        logger.error(f"Profile error: {e}")
        flash('Error loading profile', 'danger')
        return redirect(url_for('dashboard'))

# Creator Public Profile
@app.route('/creator/<creator_id>')
def creator_profile(creator_id):
    """View public creator profile"""
    try:
        # Get creator info
        creator_response = users_table.get_item(Key={'user_id': creator_id})
        creator = creator_response.get('Item')
        
        if not creator:
            flash('Creator not found', 'danger')
            return redirect(url_for('browse'))
        
        # Get creator's videos
        try:
            response = videos_table.query(
                IndexName='CreatorIndex',
                KeyConditionExpression="creator_id = :creator_id",
                ExpressionAttributeValues={":creator_id": creator_id}
            )
            videos = response.get('Items', [])
        except:
            response = videos_table.scan(
                FilterExpression="creator_id = :creator_id AND #status = :status",
                ExpressionAttributeNames={'#status': 'status'},
                ExpressionAttributeValues={
                    ':creator_id': creator_id,
                    ':status': 'published'
                }
            )
            videos = response.get('Items', [])
        
        videos.sort(key=lambda x: x.get('uploaded_at', ''), reverse=True)
        
        return render_template('creator_profile.html', creator=creator, videos=videos)
        
    except Exception as e:
        logger.error(f"Creator profile error: {e}")
        flash('Error loading creator profile', 'danger')
        return redirect(url_for('browse'))

# API Endpoints

# API: Get all videos (with pagination support)
@app.route('/api/videos', methods=['GET'])
def api_get_videos():
    """API endpoint to retrieve all videos with pagination"""
    try:
        limit = int(request.args.get('limit', 50))
        last_key = request.args.get('last_key')
        
        scan_kwargs = {'Limit': limit}
        if last_key:
            scan_kwargs['ExclusiveStartKey'] = {'video_id': last_key}
        
        response = videos_table.scan(**scan_kwargs)
        
        return jsonify({
            'success': True,
            'videos': response.get('Items', []),
            'last_key': response.get('LastEvaluatedKey', {}).get('video_id'),
            'count': len(response.get('Items', []))
        })
        
    except Exception as e:
        logger.error(f"API get videos error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# API: Get video by ID
@app.route('/api/videos/<video_id>', methods=['GET'])
def api_get_video(video_id):
    """API endpoint to retrieve a specific video"""
    try:
        response = videos_table.get_item(Key={'video_id': video_id})
        video = response.get('Item')
        
        if not video:
            return jsonify({'success': False, 'error': 'Video not found'}), 404
        
        return jsonify({'success': True, 'video': video})
        
    except Exception as e:
        logger.error(f"API get video error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# API: Search videos
@app.route('/api/search', methods=['GET'])
def api_search():
    """API endpoint for video search"""
    query = request.args.get('q', '').strip().lower()
    
    if not query:
        return jsonify({'success': False, 'error': 'Query parameter required'}), 400
    
    try:
        response = videos_table.scan()
        all_videos = response.get('Items', [])
        
        results = []
        for video in all_videos:
            if (query in video.get('title', '').lower() or
                query in video.get('creator_name', '').lower() or
                any(query in tag.lower() for tag in video.get('genre_tags', []))):
                results.append(video)
        
        return jsonify({
            'success': True,
            'results': results,
            'count': len(results),
            'query': query
        })
        
    except Exception as e:
        logger.error(f"API search error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Health Check
@app.route('/health')
def health():
    """Health check endpoint for load balancers"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()}), 200

# Error Handlers
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {e}")
    return render_template('500.html'), 500

# ---------------------------------------
# Run the Flask app
# ---------------------------------------
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_ENV') == 'development'

    app.run(host='0.0.0.0', port=port, debug=debug_mode)
