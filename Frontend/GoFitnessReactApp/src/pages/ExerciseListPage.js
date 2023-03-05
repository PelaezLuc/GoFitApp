import { useContext, useState } from "react";
import { Link } from "react-router-dom";
import { AddExerciseButton } from "../components/AddExerciseButton";
import { ExerciseCard } from "../components/ExerciseCard";
import { UserAuthContext } from "../context/UserAuthContext";
import "./css/exerciseListPage.css";
import { AddExerciseModal } from "../components/AddExerciseModal";
import useWorkouts from "../hooks/useWorkouts";
import { Header } from "../components/Header";
import { Footer } from "../components/Footer"; 
import { FiltersModal } from "../components/FiltersModal";


export const ExerciseListPage = () => {
  const [stateAddModal, setStateAddModal] = useState(false);

  const [value, setValue] = useState("");

  const [showFav, setShowFav] = useState(false);

  const [showFiltersModal, setShowFiltersModal] = useState(false);

  const [filterType, setFilterType] = useState("");

  const [filterMuscleGroup, setFilterMuscleGroup] = useState("");

  const { userAuth } = useContext(UserAuthContext);

  const {
    workouts,
    loading,
    error,
    addWorkout,
    removeWorkout,
    setWorkoutLikes,
    editWorkout,
    setWorkoutFavs,
  } = useWorkouts({ value, showFav, filterType, filterMuscleGroup });

  const onChange = (e) => {
    setValue(e.target.value);
  };

  console.log(filterMuscleGroup);

  console.log(filterType);

  if (error) return <p>{error}</p>;


  return userAuth.token ? (
    <>
      <Header />
      <AddExerciseModal
        stateAddModal={stateAddModal}
        setStateAddModal={setStateAddModal}
        addWorkout={addWorkout}
      />
      <section id="exercise-list">
        <nav className="search-nav-container">
          <AddExerciseButton
            stateAddModal={stateAddModal}
            setStateAddModal={setStateAddModal}
          />
          <ul className="search-container">
            <li className="filter-menu-item">
              <span>🔎 </span>
              <input
                type="search"
                className="search-input"
                placeholder="Buscar"
                value={value}
                autoFocus
                onChange={onChange}
              />
            </li>
            <span className="item-slash"></span>
            <li className="btn-group">
              <div className="filter-menu-item">
              {userAuth.userRole === 0 ? (
                  <button className="filter-btn" onClick={() => setShowFav(!showFav)}>
                    Favoritos
                  </button>
                ) : null}
              </div>
              <div className="filter-menu-item">
                <button className="filter-btn"
                  onClick={() => setShowFiltersModal(!showFiltersModal)}
                  >
                    +Filtros
                </button>
              </div>
            </li>
          </ul>
        </nav>
        <FiltersModal
          showFiltersModal={showFiltersModal}
          setShowFiltersModal={setShowFiltersModal}
          filterType={filterType}
          setFilterType={setFilterType}
          filterMuscleGroup={filterMuscleGroup}
          setFilterMuscleGroup={setFilterMuscleGroup}
        />
        <article className="card-container">
          <ul className="exercise-card-list">
            <ExerciseCard
              loading={loading}
              workouts={workouts}
              removeWorkout={removeWorkout}
              setWorkoutLikes={setWorkoutLikes}
              editWorkout={editWorkout}
              setWorkoutFavs={setWorkoutFavs}
            />
          </ul>
        </article>
      </section>
      <Footer />
    </>
  ) : (
    <>
      <header className="excercise-header">
        <h1 className="logo-app">
          GoFit<span className="font-logo">APP</span>
        </h1>
      </header>
      <section className="no-log-section">
        <p>Para poder ver la lista de ejercicios tienes que iniciar sesión</p>
        <Link to={"/login"}>Inicia Sesión</Link>
      </section>
    </>
  );
};