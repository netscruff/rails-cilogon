class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  # devise :database_authenticatable, :registerable,
  #       :recoverable, :rememberable, :validatable, :omniauthable, omniauth_providers: %i[openid_connect]
  devise :database_authenticatable, :omniauthable, omniauth_providers: %i[openid_connect]
end
