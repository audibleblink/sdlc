require 'sinatra'
require 'sinatra/activerecord'
require 'capybara'
require 'capybara/poltergeist'

set :bind, '0.0.0.0'
set :database, adapter: 'sqlite3', database: 'blog.db'

# enable :sessions
use Rack::Session::Cookie, httponly: false

class User < ActiveRecord::Base
  has_many :posts
end

class Post < ActiveRecord::Base
  belongs_to :user
end

# Get the homepage
get '/' do
  @posts = Post.order('created_at DESC')
  erb :"posts/index"
end

# Get the new post form
get '/posts/new' do
  redirect '/login' unless logged_in?
  @title = 'New Post'
  @post = Post.new
  erb :"posts/new"
end

post '/posts' do
  redirect '/login' unless logged_in?
  @post = Post.new(params[:post])
  @post.user = current_user
  if @post.save
    redirect "posts/#{@post.id}"
  else
    erb :"posts/new"
  end
end

get '/posts/:id' do
  @post = Post.find(params[:id])
  @title = @post.title
  erb :"posts/show"
end

get '/login' do
  erb :"session/new"
end

post '/session/new' do
  @user = User.find_by(name: params[:user][:name])
  if @user && @user.password == params[:user][:password]
    session[:user] = @user.id
    redirect :"posts/new"
  else
    redirect '/'
  end
end

get '/reset' do
  session.clear
  User.destroy_all
  Post.destroy_all
  User.create(name: 'dade', password: 'zeroc00l', is_admin: false)
  admin = User.create(name: 'admin', password: 'Winter17', is_admin: true)
  Post.create!(title: 'HELLO WORLD', body: 'FIRST!', user: admin)
  redirect '/'
end

get '/phish' do
  erb :'phish/index'
end

post '/phish' do
  authed_browser.visit(params[:url])
  <<-RESPONSE
  Admin user has clicked your link.
  <a href="/"> Go Home </a>
  RESPONSE
end

get '/search' do
  erb :'search/index'
end

## HELPERS
helpers do
  def authed_browser
    browser = Capybara::Session.new(:poltergeist)
    browser.visit 'http://localhost:4567/login'
    browser.fill_in 'user_name', with: 'admin'
    browser.fill_in 'user_password', with: 'Winter17'
    browser.click_button 'Log In'
    browser
  end

  def current_user
    current_id = session[:user]
    User.find_by!(id: current_id)
  end

  def logged_in?
    true if session[:user]
  end

  def title
    @title ? "#{@title} -- My Blog" : 'My Blog'
  end

  def pretty_date(time)
    time.strftime('%d %m %Y')
  end
end
