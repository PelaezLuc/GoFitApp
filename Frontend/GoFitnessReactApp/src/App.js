import './App.css';
import { Routes, Route } from 'react-router-dom';
//import { HomePage } from './pages/HomePage';
import { RegisterPage } from './pages/RegisterPage';
import { LoginPage } from './pages/LoginPage';
import { ExerciseListPage } from './pages/ExerciseListPage';
import { HomePage } from './pages/HomePage';

function App() {
  return (
    <main>
      <Routes>
        <Route path='/' element={<HomePage />} />
        <Route path='/app' element={<ExerciseListPage />} />
        <Route path='/register' element={<RegisterPage />} />
        <Route path='/login' element={<LoginPage />} />
      </Routes>  
    </main>   
  );
}

export default App;
