package com.example.springbootspringsecurityrefreshtokenjwtrestapi.models;

import javax.persistence.*;

@Entity
@Table(name = "roles", catalog = "dbo")
public class Role {
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Integer id;

	@Enumerated(EnumType.STRING)
	@Column(name = "name", length = 20)
	private ERole rolename;

	public Role() {
	}

	public Role(ERole rolename) {
		this.rolename = rolename;
	}

	public Integer getId() {
		return id;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	public ERole getRoleName() {
		return rolename;
	}

	public void setRoleName(ERole rolename) {
		this.rolename = rolename;
	}
}