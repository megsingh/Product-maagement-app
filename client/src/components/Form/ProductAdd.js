import React, { useState } from 'react'
import { useHistory } from 'react-router-dom'
import axios from 'axios'
import jwt_decode from "jwt-decode"
import { getToken } from '../utils/authOperations'

import "./form.css"

function ProductAdd() {
  const history = useHistory()

  const [product, setProduct] = useState({
    title: "",
    author: "",
    delivered: false
  })

  const onSubmit = (e) => {
    e.preventDefault();
    const productData = {
      title: product.title,
      author: product.author,
      delivered: product.delivered,
    };
    console.log(productData);
    let config = {
      headers: {
        Authorization: 'Bearer ' + getToken()
      }
    }

    axios.post(`http://localhost:5000/api/products/add`, productData, config)
      .then(res => {
        console.log(res);
        window.location.href = "/products";
      })
      .catch(err => console.log(err)
      );
  };

  const handleLogout = () => {
    if (window.confirm("Are you sure you want to logout?") === true) {
      localStorage.removeItem("user")
      history.push("/")
    }
  }


  return (
    <div className='product__add'>
      <div>
        <a href='/' className='logout__button' onClick={handleLogout}>Logout</a>
      </div>
      <div className="add__header">
        <h4 className='add__title'>
          <b>Add a new Product</b>
        </h4>
      </div>
      <form noValidate onSubmit={onSubmit}>
        <div>
          <label className='add__label' htmlFor="name">Title</label>
          <input className='add__input'
            onChange={(e) => setProduct({ ...product, title: e.target.value })}
            value={product.title}
            id="title"
            type="text"
          />

        </div>

        <div>
          <label className='add__label' htmlFor="locatioon">Author</label>
          <input className='add__input'
            onChange={(e) => setProduct({ ...product, author: e.target.value })}
            value={product.author}
            id="author"
            type="text"
          />

        </div>


        <div className='add__submit'>
          <button className='add__button' type="submit">Add Product</button>
        </div>
      </form>
    </div>
  )
}

export default ProductAdd