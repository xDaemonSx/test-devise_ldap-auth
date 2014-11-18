class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable, :validatable
  devise :ldap_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable

  before_save :get_ldap_email

  def get_ldap_email
    self.email = Devise::LDAP::Adapter.get_ldap_param(self.username,"mail")
  end
end
