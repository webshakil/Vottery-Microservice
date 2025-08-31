//latest
import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router'
import App from './App.jsx'
import { AuthProvider } from './contexts/AuthContext.jsx'
import { SecurityProvider } from './contexts/SecurityContext.jsx'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter>
      <SecurityProvider> 
        <AuthProvider> 
          <App />
        </AuthProvider> 
      </SecurityProvider> 
    </BrowserRouter>
  </React.StrictMode>,
)





// import React from 'react'
// import ReactDOM from 'react-dom/client'
// import { BrowserRouter } from 'react-router'
// import App from './App.jsx'
// import { AuthProvider } from './contexts/AuthContext.jsx'
// import { SecurityProvider } from './contexts/SecurityContext.jsx'
// import './index.css'

// ReactDOM.createRoot(document.getElementById('root')).render(
//   <React.StrictMode>
//     <BrowserRouter>
//       <SecurityProvider>
//         <AuthProvider>
//           <App />
//         </AuthProvider>
//       </SecurityProvider>
//     </BrowserRouter>
//   </React.StrictMode>,
// )

