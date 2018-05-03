Rails.application.routes.draw do
  devise_for :users
  resources :users do
  	collection do 
  		get 'callback'
  		get 'display'
  		get 'logout'
  	end
  end
  root "users#login"
end
