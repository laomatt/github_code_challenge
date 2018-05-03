class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable

	def self.from_omniauth(auth)
    if User.exists?(:email => auth.info.email)
      user = User.find_by_email(auth.info.email)
      user.update_attributes(avatar_url: auth.info.image)
      user
    else
      user = User.create(name: auth.extra.raw_info.name, email: auth.info.email, avatar_url: auth.info.image, password: Devise.friendly_token[0,20])
    end
    user
  end

  def self.new_with_session(params, session)
    super.tap do |user|
      if data = session["devise.github_data"] && session["devise.github_data"]["extra"]["raw_info"]
        user.email = data["email"] if user.email.blank?
      end
    end
  end
end
